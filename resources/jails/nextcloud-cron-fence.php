<?php
declare(strict_types=1);

// Installation-only scheduling fence checks. No Nextcloud bootstrap or secrets.
function cronRequire(bool $condition): void {
    if (!$condition) {
        throw new RuntimeException('Cron fence identity or closure check failed.');
    }
}

function cronCommand(array $command): array {
    $process = proc_open($command, [0 => ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['PATH' => '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL' => 'C']);
    cronRequire(is_resource($process));
    $out = $err = '';
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $deadline = hrtime(true) + 5_000_000_000;
    try {
        do {
            $status = proc_get_status($process);
            $out .= stream_get_contents($pipes[1]);
            $err .= stream_get_contents($pipes[2]);
            cronRequire(strlen($out) + strlen($err) <= 4 * 1024 * 1024);
            if (!$status['running']) {
                break;
            }
            cronRequire(hrtime(true) < $deadline);
            usleep(10000);
        } while (true);
    } catch (Throwable $error) {
        // Only this helper's directly spawned ps/crontab process, never a writer.
        proc_terminate($process, 9);
        throw $error;
    } finally {
        fclose($pipes[1]);
        fclose($pipes[2]);
        $closed = proc_close($process);
    }
    return [$status['exitcode'] >= 0 ? $status['exitcode'] : $closed, $out, $err];
}

function cronProcesses(string $text): array {
    $rows = [];
    foreach (explode("\n", trim($text)) as $line) {
        cronRequire((bool)preg_match('/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$/D', $line, $m));
        $pid = (int)$m[1];
        cronRequire($pid > 0 && !isset($rows[$pid]));
        $rows[$pid] = ['parent' => (int)$m[2], 'uid' => (int)$m[3], 'name' => basename($m[4])];
    }
    return $rows;
}

// Read only the two configured native scanner pidfiles. Never trust a scanner
// name or account alone, nor a pidfile reached through writable/symlink parents.
function cronScannerPids(int $uid, ?callable $stat = null, ?callable $read = null): array {
    $stat ??= 'lstat';
    $read ??= fn($path) => file_get_contents($path, false, null, 0, 33);
    cronRequire($uid > 0);
    foreach (['/', '/var', '/var/run', '/var/run/clamav'] as $path) {
        clearstatcache(true, $path);
        $info = $stat($path);
        cronRequire(is_array($info) && ($info['mode'] & 0170000) === 0040000
            && in_array($info['uid'], $path === '/var/run/clamav' ? [0, $uid] : [0], true)
            && ($info['mode'] & 0022) === 0);
    }
    $pids = [];
    foreach (['clamd', 'freshclam'] as $name) {
        $path = '/var/run/clamav/' . $name . '.pid';
        clearstatcache(true, $path);
        $before = $stat($path);
        cronRequire(is_array($before) && ($before['mode'] & 0170000) === 0100000
            && in_array($before['uid'], [0, $uid], true) && ($before['mode'] & 0022) === 0
            && $before['nlink'] === 1 && $before['size'] > 0 && $before['size'] <= 32);
        $text = $read($path);
        clearstatcache(true, $path);
        $after = $stat($path);
        $keys = array_flip(['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime', 'ctime']);
        cronRequire(is_array($after) && array_intersect_key($before, $keys) === array_intersect_key($after, $keys)
            && is_string($text) && strlen($text) === $before['size']
            && preg_match('/^[1-9][0-9]{0,9}\n?$/D', $text));
        $pid = (int)$text;
        cronRequire(!isset($pids[$pid]));
        $pids[$pid] = ['uid' => $uid, 'name' => $name, 'file' => array_intersect_key($before, $keys)];
    }
    return $pids;
}

/** @param array<int, array{uid: int, name: string, file?: array}> $scanners */
function cronWritersClosed(array $rows, int $worker, int $helper, array $users, callable $command, array $scanners = []): bool {
    // Only this exact root worker/helper ancestry may contain shell/CLI PHP.
    cronRequire(isset($rows[$helper], $rows[$worker]) && $rows[$helper]['parent'] === $worker
        && $rows[$helper]['name'] === 'php' && $rows[$worker]['name'] === 'sh');
    $ancestors = [];
    for ($pid = $helper; isset($rows[$pid]); $pid = $rows[$pid]['parent']) {
        cronRequire(!isset($ancestors[$pid]) && $rows[$pid]['uid'] === 0
            && in_array($rows[$pid]['name'], ['php', 'sh', 'jexec', 'init'], true));
        $ancestors[$pid] = true;
    }
    $services = ['init' => [0], 'syslogd' => [0], 'httpd' => [0, $users['www']],
        'php-fpm' => [0, $users['www']], 'mariadbd' => [$users['mysql']],
        'mysqld' => [$users['mysql']], 'redis-server' => [$users['redis']]];
    foreach ($scanners as $pid => $identity) {
        if (!isset($rows[$pid]) || $rows[$pid]['uid'] !== $identity['uid']
            || $rows[$pid]['name'] !== $identity['name']) {
            return false;
        }
        [$code, $args, $error] = $command(['/bin/ps', '-ww', '-p', (string)$pid, '-o', 'args=']);
        $pattern = match ($identity['name']) {
            'clamd' => '~^/usr/local/sbin/clamd$~D',
            'freshclam' => '~^/usr/local/bin/freshclam --daemon -p /var/run/clamav/freshclam\.pid$~D',
            default => '',
        };
        if ($code !== 0 || $error !== '' || $pattern === '' || !preg_match($pattern, trim($args))) {
            return false;
        }
    }
    foreach ($rows as $pid => $row) {
        if (isset($ancestors[$pid])) {
            continue;
        }
        if (isset($scanners[$pid])) {
            continue;
        }
        if ($row['name'] === 'ps' && $row['uid'] === 0 && $row['parent'] === $helper) {
            continue;
        }
        if (isset($services[$row['name']]) && in_array($row['uid'], $services[$row['name']], true)) {
            continue;
        }
        // The ports database rc script retains a shell supervisor. Verify its
        // exact script prefix and live database child, never allow shells by UID.
        if ($row['name'] === 'sh' && in_array($row['uid'], [0, $users['mysql']], true)) {
            $databaseChild = false;
            foreach ($rows as $child) {
                $databaseChild = $databaseChild || ($child['parent'] === $pid && $child['uid'] === $users['mysql']
                    && in_array($child['name'], ['mariadbd', 'mysqld'], true));
            }
            if ($databaseChild) {
                [$code, $args, $error] = $command(['/bin/ps', '-ww', '-p', (string)$pid, '-o', 'args=']);
                // Captured locally only; neither arguments nor inventory appear
                // in diagnostics (including when this identity check refuses).
                if ($code === 0 && $error === '' && preg_match('~^/bin/sh /usr/local/bin/(?:mariadbd|mysqld)-safe(?:\s|$)~D', trim($args))) {
                    continue;
                }
            }
        }
        return false;
    }
    return true;
}

function cronWaitClosed(int $worker, int $helper, array $users, callable $command, callable $clock, callable $sleep, ?callable $scanners = null): void {
    $deadline = $clock() + 60;
    do {
        // FreeBSD treats text after '=' as that field's header; repeat -o for
        // separate empty headers rather than GNU's combined '=,' syntax.
        $before = $scanners === null ? [] : $scanners();
        [$code, $out, $err] = $command(['/bin/ps', '-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'uid=', '-o', 'comm=']);
        cronRequire($code === 0 && $err === '');
        if (cronWritersClosed(cronProcesses($out), $worker, $helper, $users, $command, $before)
            && ($scanners === null || $before === $scanners())) {
            return;
        }
        cronRequire($clock() < $deadline);
        $sleep();
    } while (true);
}

function cronTableMetadata(string $root, ?callable $stat = null, ?callable $scan = null): ?array {
    $stat ??= 'lstat';
    $scan ??= 'scandir';
    foreach (['/', '/var', '/var/cron', '/var/cron/tabs'] as $suffix) {
        $path = $root . $suffix;
        clearstatcache(true, $path);
        $info = $stat($path);
        cronRequire(is_array($info) && ($info['mode'] & 0170000) === 0040000
            && $info['uid'] === 0 && ($info['mode'] & 0022) === 0);
        if ($suffix === '/var/cron/tabs') {
            cronRequire(($info['mode'] & 0777) === 0700);
        }
    }
    $path = $root . '/var/cron/tabs/www';
    clearstatcache(true, $path);
    $names = $scan($root . '/var/cron/tabs');
    cronRequire(is_array($names) && in_array('.', $names, true) && in_array('..', $names, true)
        && count($names) === count(array_unique($names))
        && array_diff($names, ['.', '..', 'www']) === []);
    if (!in_array('www', $names, true)) {
        return null;
    }
    $info = $stat($path);
    cronRequire(is_array($info) && ($info['mode'] & 0170000) === 0100000 && $info['uid'] === 0
        && ($info['mode'] & 0777) === 0600 && $info['nlink'] === 1 && $info['size'] <= 65536);
    // Listing reads the file and may update atime; identity and content-related
    // metadata must remain stable, not the read-access timestamp.
    return array_intersect_key($info, array_flip(['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime', 'ctime']));
}

function cronTableState(?array $before, ?array $after, array $result, string $template): string {
    cronRequire($before === $after);
    [$code, $out, $err] = $result;
    if ($before === null) {
        cronRequire($code === 1 && $out === '' && $err === "crontab: no crontab for www\n");
        return 'absent';
    }
    cronRequire($code === 0 && $err === '' && $out === $template);
    return 'present';
}

function cronFenceMain(array $args): int {
    try {
        cronRequire(PHP_OS_FAMILY === 'BSD' && posix_getuid() === 0);
        if ((count($args) === 3 || (count($args) === 4 && $args[3] === '--antivirus'))
            && $args[1] === 'closed' && ctype_digit($args[2])) {
            $users = [];
            foreach (['www', 'mysql', 'redis'] as $name) {
                $entry = posix_getpwnam($name);
                cronRequire(is_array($entry));
                $users[$name] = $entry['uid'];
            }
            $scanners = null;
            if (count($args) === 4) {
                $entry = posix_getpwnam('clamav');
                cronRequire(is_array($entry) && $entry['uid'] > 0);
                $uid = $entry['uid'];
                $scanners = fn() => cronScannerPids($uid);
            }
            cronWaitClosed((int)$args[2], getmypid(), $users, 'cronCommand', fn() => hrtime(true) / 1e9, fn() => usleep(200000), $scanners);
        } elseif (count($args) === 3 && $args[1] === 'table') {
            $before = cronTableMetadata('');
            $result = cronCommand(['/usr/bin/crontab', '-u', 'www', '-l']);
            $after = cronTableMetadata('');
            $template = file_get_contents($args[2]);
            cronRequire(is_string($template) && strlen($template) < 65536);
            echo cronTableState($before, $after, $result, $template), "\n";
        } else {
            cronRequire(false);
        }
        return 0;
    } catch (Throwable $error) {
        fwrite(STDERR, "Cron fence check failed; retain stopped scheduling and inspect privately.\n");
        return 1;
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(cronFenceMain($argv));
}
