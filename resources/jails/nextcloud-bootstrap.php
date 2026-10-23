<?php
declare(strict_types=1);

/* CLI only. runtime.json is PUBLIC configuration; secret objects arrive only on
 * stdin. www inherits a root-opened descriptor 3 for that same public file, since
 * /root/cloud-installer remains 0700. Connector installation additionally receives
 * the locked public release record on fd4. No combined credential document is written.
 * Define CLOUD_NEXTCLOUD_LIBRARY to test the pure functions without provisioning.
 * Interfaces checked against nextcloud/server stable35 (2026-10-14):
 * core/Command/Maintenance/Install.php, lib/private/Setup.php,
 * lib/private/Console/Application.php, lib/public/IAppConfig.php,
 * lib/private/AppConfig.php, lib/private/AppFramework/Http/Request.php.
 */

const CLOUD_APP = '/usr/local/www/nextcloud';
const CLOUD_RUNTIME = '/root/cloud-installer/runtime.json';

// Only our fixed diagnostic codes are printable. Upstream errors can contain
// SQL, password verifiers or input values, even with exception arguments hidden.
final class CloudFailure extends RuntimeException {}

function cloudFail(int $code): never {
    throw new CloudFailure('', $code);
}

function cloudDiagnostic(Throwable $error): string {
    $messages = [
        10 => 'Invalid public configuration or phase input.',
        11 => 'Expected root database helper or www application helper.',
        12 => 'Selected Nextcloud code is missing, incomplete or different; inspect the prepare phase.',
        13 => 'The PHP interpreter must match the selected numeric upstream version and use 64-bit integers.',
        20 => 'Uncertain Nextcloud initialization: tables or data exist without a complete matching installation. Stop and inspect the host pre-install checkpoint; explicitly restore the coherent app/data/database checkpoint or recover manually before resuming. Nothing was deleted.',
        21 => 'Existing Nextcloud instance, administrator, hostname or database configuration does not match the immutable deployment.',
        22 => 'Nextcloud is in maintenance mode or needs an upgrade; resolve this before resuming.',
        23 => 'Database account or schema differs from this deployment; credentials were not changed.',
        24 => 'Nextcloud CLI installation failed. Inspect PHP extensions, directory permissions and MariaDB availability, then retry only if the database is still empty; otherwise use the host pre-install checkpoint.',
        25 => 'ONLYOFFICE is missing, disabled or incompatible with the selected Nextcloud; install a signed compatible release without force.',
        26 => 'Unable to connect to the managed database; check the service/socket and host-retained credentials.',
        27 => 'Unable to write the managed application configuration.',
        28 => 'Initialization checkpoint requires an unconfigured application, an empty Nextcloud database and an empty data directory. An existing installation cannot become a new initialization checkpoint.',
        29 => 'Connector authentication is incomplete or changed. Retain the original connector.json and app tree; explicit recovery is required before retrying. Automatic overwrite or adoption is refused.',
        30 => 'Nextcloud mimetype migrations remain pending after native repair; publication is blocked. Retry the installation phase or inspect the host pre-install checkpoint.',
    ];
    return $error instanceof CloudFailure
        ? ($messages[$error->getCode()] ?? 'Nextcloud helper failed.')
        : 'Nextcloud helper failed; inspect service health and the immutable deployment inputs. Raw exception output was suppressed.';
}

function cloudDecode(string $input): array {
    if (strlen($input) > 65536) {
        cloudFail(10);
    }
    $config = json_decode($input, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($config) || array_is_list($config)) {
        cloudFail(10);
    }
    return $config;
}

function cloudRead($stream): array {
    $input = stream_get_contents($stream, 65537);
    if ($input === false) {
        cloudFail(10);
    }
    return cloudDecode($input);
}

function cloudString(mixed $value, int $min = 0, int $max = 1024): bool {
    return is_string($value) && strlen($value) >= $min && strlen($value) <= $max
        && !preg_match('/[\x00-\x1f\x7f]/', $value);
}

function cloudVersions(mixed $value): array {
    $patterns = [
        'nextcloud' => '[0-9]+\.[0-9]+\.[0-9]+',
        'onlyoffice' => '[0-9]+\.[0-9]+\.[0-9]+',
        'connector' => '[0-9]+\.[0-9]+\.[0-9]+',
        'connector_sha256' => '[a-f0-9]{64}',
        'php' => '[0-9]+(?:\.[0-9]+)+',
        'database' => '[0-9]+(?:\.[0-9]+)+',
        'freebsd_release' => '[0-9]+\.[0-9]+-RELEASE',
        'architecture' => '[a-z][a-z0-9_]*',
        'php_package' => 'php[0-9]+',
        'plan_sha256' => '[a-f0-9]{64}',
        'packages_sha256' => '[a-f0-9]{64}',
        'dependencies_sha256' => '[a-f0-9]{64}',
    ];
    if (is_array($value) && ($value['office_backend'] ?? null) === 'none') {
        unset($patterns['onlyoffice'], $patterns['connector'], $patterns['connector_sha256']);
        $patterns['office_backend'] = 'none';
    } elseif (is_array($value) && in_array($value['office_backend'] ?? null, ['eurooffice', 'collabora'], true)) {
        unset($patterns['onlyoffice']);
        $patterns['office_backend'] = '(?:eurooffice|collabora)';
        $patterns['connector_app'] = $value['office_backend'] === 'eurooffice' ? 'eurooffice' : 'richdocuments';
    }
    if (!is_array($value) || array_diff(array_keys($value), array_keys($patterns))
        || array_diff(array_keys($patterns), array_keys($value))) {
        cloudFail(10);
    }
    foreach ($patterns as $key => $pattern) {
        if (!cloudString($value[$key], 1, 128) || !preg_match('~\A' . $pattern . '\z~', $value[$key])) {
            cloudFail(10);
        }
    }
    return $value;
}

function cloudPHPEnvironment(array $c, string $actual = PHP_VERSION, int $integerSize = PHP_INT_SIZE): void {
    if ($actual !== $c['versions']['php'] || $integerSize !== 8
        || !preg_match('/\A[0-9]+(?:\.[0-9]+)+\z/', $actual)) {
        cloudFail(13);
    }
}

function cloudApps(mixed $selection): array {
    if (!is_string($selection)) {
        cloudFail(10);
    }
    if ($selection === '' || $selection === 'none') {
        return [];
    }
    $apps = explode(',', $selection);
    $sorted = $apps;
    sort($sorted, SORT_STRING);
    if ($apps !== $sorted || count(array_unique($apps)) !== count($apps)) {
        cloudFail(10);
    }
    foreach ($apps as $id) {
        if (!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/', $id)
            || in_array($id, ['none', 'onlyoffice', 'eurooffice', 'richdocuments', 'richdocumentscode', 'richdocumentscode_arm64'], true)) {
            cloudFail(10);
        }
    }
    return $apps;
}

// app:list's disabled entry describes code on disk, NOT completed installation.
// Require the separate native installed_version to match before enabling it.
function cloudOptionalAppState(string $id, mixed $list, string $installed): string {
    if (cloudApps($id) !== [$id] || !is_array($list)
        || !is_array($list['enabled'] ?? null) || !is_array($list['disabled'] ?? null)) {
        cloudFail(10);
    }
    $installed = rtrim($installed, "\r\n");
    $enabled = array_key_exists($id, $list['enabled']);
    $disabled = array_key_exists($id, $list['disabled']);
    if ($enabled && !$disabled && cloudString($installed, 1, 128)
        && $list['enabled'][$id] === $installed) {
        return 'enabled';
    }
    if ($disabled && !$enabled && cloudString($installed, 1, 128)
        && $list['disabled'][$id] === $installed . ' (installed ' . $installed . ')') {
        return 'disabled';
    }
    if (!$enabled && !$disabled && $installed === '') {
        return 'missing';
    }
    cloudFail(10); // Partial code/migration, stale inventory or ambiguous status.
}

function cloudValidate(array $c): array {
    $c['versions'] = cloudVersions($c['versions'] ?? null);
    $none = ($c['versions']['office_backend'] ?? null) === 'none';
    $strings = ['public_hostname', 'public_url', 'storage_url', 'nextcloud_ip', 'onlyoffice_ip',
        'admin_username', 'db_name', 'timezone', 'admin_email', 'tls_mode', 'acme_email', 'repository'];
    if ($none) {
        $strings = array_values(array_diff($strings, ['storage_url', 'onlyoffice_ip']));
    }
    $budgets = ['php_memory_mb' => [512, 32768], 'php_children' => [$none ? 2 : 3, 512],
        'db_buffer_mb' => [128, 1048576], 'redis_memory_mb' => [32, 32768],
        'upload_max_mb' => [1, 1048576]];
    // An allowlist also rejects accidentally staged passwords/JWTs, including
    // unknown nested credential bundles. Nothing in this file is secret input.
    $keys = array_merge($strings, array_keys($budgets), ['proxy_networks', 'versions']);
    if (array_diff(array_keys($c), array_merge($keys, ['nextcloud_apps'])) || array_diff($keys, array_keys($c))) {
        cloudFail(10);
    }
    if (array_key_exists('nextcloud_apps', $c)) {
        cloudApps($c['nextcloud_apps']);
    }
    foreach ($strings as $key) {
        if (!cloudString($c[$key])) {
            cloudFail(10);
        }
    }
    if (strlen($c['public_hostname']) > 253 || !preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z/', $c['public_hostname'])
        || filter_var($c['public_hostname'], FILTER_VALIDATE_IP)) {
        cloudFail(10);
    }
    foreach ($none ? ['nextcloud_ip'] : ['nextcloud_ip', 'onlyoffice_ip'] as $key) {
        if (!filter_var($c[$key], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            cloudFail(10);
        }
        $octets = array_map('intval', explode('.', $c[$key]));
        if (!($octets[0] === 10 || ($octets[0] === 172 && $octets[1] >= 16 && $octets[1] <= 31)
            || ($octets[0] === 192 && $octets[1] === 168))) {
            cloudFail(10);
        }
    }
    if ((!$none && $c['nextcloud_ip'] === $c['onlyoffice_ip'])
        || !preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/', $c['admin_username'])
        || $c['db_name'] !== 'nextcloud'
        || !in_array($c['timezone'], timezone_identifiers_list(DateTimeZone::ALL_WITH_BC), true)
        || !in_array($c['tls_mode'], ['acme', 'provided', 'external'], true)
        || !in_array($c['repository'], ['latest', 'quarterly'], true)) {
        cloudFail(10);
    }
    if (!preg_match('~\Ahttps://' . preg_quote($c['public_hostname'], '~') . '(?::([1-9][0-9]{0,4}))?/\z~', $c['public_url'], $url)
        || (isset($url[1]) && (int)$url[1] > 65535)) {
        cloudFail(10);
    }
    $storage = $c['tls_mode'] === 'external' ? 'http://' . $c['nextcloud_ip'] . '/'
        : 'https://' . $c['public_hostname'] . '/';
    if ((!$none && $c['storage_url'] !== $storage) || !is_array($c['proxy_networks']) || !array_is_list($c['proxy_networks'])
        || count($c['proxy_networks']) > 64
        || ($c['tls_mode'] === 'external') !== (count($c['proxy_networks']) > 0)) {
        cloudFail(10);
    }
    foreach ($c['proxy_networks'] as $network) {
        if (!is_string($network) || !preg_match('~\A([0-9.]+)/([1-9]|[12][0-9]|3[0-2])\z~', $network, $parts)
            || !filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            cloudFail(10);
        }
        $mask = (0xffffffff << (32 - (int)$parts[2])) & 0xffffffff;
        if ((ip2long($parts[1]) & $mask) !== ip2long($parts[1])) {
            cloudFail(10);
        }
    }
    if (count(array_unique($c['proxy_networks'])) !== count($c['proxy_networks'])) {
        cloudFail(10);
    }
    foreach (['admin_email', 'acme_email'] as $key) {
        if ($key === 'acme_email' && $c['tls_mode'] !== 'acme' && $c[$key] === '') {
            continue;
        }
        if (!filter_var($c[$key], FILTER_VALIDATE_EMAIL)
            || !preg_match('/\A[A-Za-z0-9_.+%\-]+@[A-Za-z0-9.\-]+\z/', $c[$key])) {
            cloudFail(10);
        }
    }
    foreach ($budgets as $key => [$min, $max]) {
        if (!is_int($c[$key]) || $c[$key] < $min || $c[$key] > $max) {
            cloudFail(10);
        }
    }
    return $c;
}

function cloudSecrets(array $input, string $phase): array {
    $keys = match ($phase) {
        'database', 'checkpoint-ready' => ['db_password' => 12],
        'install' => ['admin_password' => 14, 'db_password' => 12],
        default => throw new CloudFailure('', 10),
    };
    if (array_diff(array_keys($input), array_keys($keys)) || array_diff(array_keys($keys), array_keys($input))) {
        cloudFail(10);
    }
    foreach ($keys as $key => $minimum) {
        if (!cloudString($input[$key], $minimum)) {
            cloudFail(10);
        }
    }
    return $input;
}

function cloudAuthority(array $c): string {
    return substr($c['public_url'], strlen('https://'), -1);
}

function cloudIdentity(array $c): string {
    ksort($c);
    return hash('sha256', json_encode($c, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
}

function cloudTokens(array $c): array {
    // Synchronous office previews need a callback to fetch the source file.
    // Reserve capacity rather than letting previews consume every PHP slot.
    $none = ($c['versions']['office_backend'] ?? null) === 'none';
    $callbacks = $none ? 0 : ($c['php_children'] >= 4 ? 2 : 1);
    $children = $c['php_children'] - $callbacks;
    $spare = max(1, intdiv($children, 4));
    $tls = $c['tls_mode'] === 'acme'
        ? '/usr/local/etc/letsencrypt/live/' . $c['public_hostname'] : '/usr/local/etc/cloud-tls';
    return [
        'PUBLIC_HOSTNAME' => $c['public_hostname'], 'PUBLIC_AUTHORITY' => cloudAuthority($c),
        'ADMIN_EMAIL' => $c['admin_email'], 'TIMEZONE' => $c['timezone'],
        'NEXTCLOUD_IP' => $c['nextcloud_ip'],
        ...($none ? [] : ['ONLYOFFICE_IP' => $c['onlyoffice_ip']]),
        'HTTP_CLIENTS' => implode(' ', array_merge($c['proxy_networks'], $none ? [] : [$c['onlyoffice_ip']], [$c['nextcloud_ip'], '127.0.0.1'])),
        'PHP_MEMORY_MB' => $c['php_memory_mb'], 'PHP_CHILDREN' => $children, 'PHP_MIN_SPARE' => $spare,
        'PHP_START_SERVERS' => min($children, max(2, $spare)),
        'PHP_MAX_SPARE' => min($children, max(2, intdiv($children, 2))),
        ...($none ? [] : ['PHP_CALLBACK_CHILDREN' => $callbacks]),
        'DB_BUFFER_MB' => $c['db_buffer_mb'], 'DB_CONNECTIONS' => max(32, $c['php_children'] + 16),
        'REDIS_MEMORY_MB' => $c['redis_memory_mb'], 'UPLOAD_MAX_MB' => $c['upload_max_mb'],
        'POST_MAX_MB' => $c['upload_max_mb'] + 16,
        'TLS_CHAIN' => $tls . '/fullchain.pem', 'TLS_KEY' => $tls . '/privkey.pem',
        'TLS_MODULES' => $c['tls_mode'] === 'external' ? '# TLS terminates at the external HTTPS proxy.'
            : "LoadModule ssl_module libexec/apache24/mod_ssl.so\nLoadModule socache_shmcb_module libexec/apache24/mod_socache_shmcb.so\nSSLSessionCache \"shmcb:/var/run/ssl_scache(512000)\"\nSSLSessionCacheTimeout 300",
    ];
}

function cloudRender(string $template, array $c): string {
    $tokens = cloudTokens($c);
    return preg_replace_callback('/@@([A-Z0-9_]+)@@/', static function (array $match) use ($tokens): string {
        if (!array_key_exists($match[1], $tokens)) {
            cloudFail(10);
        }
        return (string)$tokens[$match[1]];
    }, $template);
}

// Preserve packaged FPM defaults/comments, replacing only managed settings.
// PHP itself uses the production INI plus a separate late-loading drop-in.
function cloudPatchIni(string $base, string $overrides): string {
    $section = '';
    $managed = [];
    foreach (explode("\n", $overrides) as $line) {
        if (preg_match('/^\s*\[([^]]+)\]\s*$/', $line, $m)) {
            $section = $m[1];
        } elseif (preg_match('/^\s*([^;#][^=]*?)\s*=\s*(.*?)\s*$/', $line, $m)) {
            $managed[$section][trim($m[1])] = $m[2];
        }
    }
    $section = '';
    $result = [];
    $written = [];
    $sections = [];
    $flush = static function (string $name) use (&$result, &$written, $managed): void {
        foreach ($managed[$name] ?? [] as $key => $value) {
            if (!isset($written[$name][$key])) {
                $result[] = $key . ' = ' . $value;
                $written[$name][$key] = true;
            }
        }
    };
    foreach (explode("\n", rtrim($base)) as $line) {
        // FPM includes are parsed inline and can leave the active section in
        // an included pool. Emit missing global settings before that include,
        // never append them after it where FPM would interpret pool options.
        if (preg_match('/^\s*include\s*=/', $line)) {
            $flush($section);
        }
        if (preg_match('/^\s*\[([^]]+)\]\s*$/', $line, $m)) {
            $flush($section);
            $section = $m[1];
            $sections[$section] = true;
        } elseif (preg_match('/^\s*([^;#][^=]*?)\s*=/', $line, $m) && isset($managed[$section][trim($m[1])])) {
            $key = trim($m[1]);
            $line = isset($written[$section][$key]) ? '; cloud-installer duplicate: ' . $line
                : $key . ' = ' . $managed[$section][$key];
            $written[$section][$key] = true;
        }
        $result[] = $line;
    }
    $flush($section);
    foreach ($managed as $section => $values) {
        if ($section !== '' && !isset($sections[$section])) {
            $result[] = "\n; cloud-installer managed overrides\n[" . $section . ']';
            $flush($section);
        }
    }
    return implode("\n", $result) . "\n";
}

function cloudSystemConfig(array $c): array {
    $domains = array_values(array_unique([cloudAuthority($c), $c['public_hostname']]));
    $none = ($c['versions']['office_backend'] ?? null) === 'none';
    if (!$none && $c['tls_mode'] === 'external') {
        $domains[] = $c['nextcloud_ip']; // ONLYOFFICE's direct HTTP storage/callback URL.
    }
    return [
        'trusted_domains' => $domains,
        'trusted_proxies' => $c['tls_mode'] === 'external' ? $c['proxy_networks'] : [],
        'forwarded_for_headers' => ['HTTP_X_FORWARDED_FOR'],
        'overwrite.cli.url' => $c['public_url'],
        'overwritehost' => cloudAuthority($c), 'overwriteprotocol' => 'https',
        'htaccess.RewriteBase' => '/', 'datadirectory' => '/var/nc-data',
        'tempdirectory' => '/var/nc-tmp/nextcloud',
        'apps_paths' => [
            ['path' => '/usr/local/www/nextcloud/apps', 'url' => '/apps', 'writable' => false],
            ['path' => '/usr/local/www/nextcloud/custom_apps', 'url' => '/custom_apps', 'writable' => true],
        ],
        'upgrade.disable-web' => true,
        'setup_create_db_user' => false, 'mysql.utf8mb4' => true,
        'filelocking.enabled' => true, 'memcache.local' => '\\OC\\Memcache\\APCu',
        'memcache.distributed' => '\\OC\\Memcache\\Redis', 'memcache.locking' => '\\OC\\Memcache\\Redis',
        'redis' => ['host' => '/var/run/redis/private/nextcloud.sock', 'port' => 0, 'timeout' => 1.5],
        ...($none ? [] : ['allow_local_remote_servers' => true]), // Private ONLYOFFICE, not a TLS-verification bypass.
        'maintenance_window_start' => 1,
        'log_type' => 'file', 'logfile' => '/var/log/nextcloud/nextcloud.log',
        'loglevel' => 2, 'logtimezone' => $c['timezone'], 'logdateformat' => 'Y-m-d H:i:s T',
        'log_rotate_size' => 104857600, 'debug' => false, 'profiler' => false,
        'mail_smtpmode' => 'null', // No SMTP relay was requested/verified.
        'mail_from_address' => 'cloud', 'mail_domain' => $c['public_hostname'],
    ];
}

function cloudConnector(array $connector, array $c): array {
    if (($c['versions']['office_backend'] ?? 'onlyoffice') !== 'onlyoffice'
        || array_keys($connector) !== ['apps'] || !is_array($connector['apps'])
        || array_keys($connector['apps']) !== ['onlyoffice'] || !is_array($connector['apps']['onlyoffice'])) {
        cloudFail(10);
    }
    $app = $connector['apps']['onlyoffice'];
    $keys = ['DocumentServerUrl', 'DocumentServerInternalUrl', 'StorageUrl', 'jwt_secret', 'jwt_header', 'verify_peer_off'];
    if (array_diff(array_keys($app), $keys) || array_diff($keys, array_keys($app))) {
        cloudFail(10);
    }
    foreach ($app as $value) {
        if (!cloudString($value)) {
            cloudFail(10);
        }
    }
    if ($app['DocumentServerUrl'] !== $c['public_url'] . 'onlyoffice/'
        || $app['DocumentServerInternalUrl'] !== 'http://' . $c['onlyoffice_ip'] . ':8081/'
        || $app['StorageUrl'] !== $c['storage_url'] || $app['jwt_header'] !== 'AuthorizationJWT'
        || $app['verify_peer_off'] !== 'false' || strlen($app['jwt_secret']) < 32) {
        cloudFail(10);
    }
    return $app;
}

function cloudVmConnector(array $connector, array $c): array {
    $backend = $c['versions']['office_backend'] ?? '';
    $appId = cloudConnectorId($c);
    if (!in_array($backend, ['eurooffice', 'collabora'], true)
        || array_keys($connector) !== ['apps'] || !is_array($connector['apps'])
        || array_keys($connector['apps']) !== [$appId] || !is_array($connector['apps'][$appId])) {
        cloudFail(10);
    }
    $app = $connector['apps'][$appId];
    $expected = $backend === 'eurooffice' ? [
        'DocumentServerUrl' => $c['public_url'] . 'eurooffice/',
        'DocumentServerInternalUrl' => 'http://' . $c['onlyoffice_ip'] . ':8081/',
        'StorageUrl' => $c['storage_url'], 'jwt_header' => 'AuthorizationJWT', 'verify_peer_off' => 'false',
    ] : [
        'wopi_url' => 'http://' . $c['onlyoffice_ip'] . ':8081/collabora/',
        'wopi_callback_url' => $c['storage_url'], 'wopi_allowlist' => $c['onlyoffice_ip'] . '/32',
    ];
    $keys = array_keys($expected);
    if ($backend === 'eurooffice') {
        $keys[] = 'jwt_secret';
        if (!cloudString($app['jwt_secret'] ?? null, 64, 64)
            || !preg_match('/\A[a-fA-F0-9]{64}\z/', $app['jwt_secret'])) {
            cloudFail(10);
        }
    }
    if (array_diff(array_keys($app), $keys) || array_diff($keys, array_keys($app))) {
        cloudFail(10);
    }
    foreach ($expected as $key => $value) {
        if (($app[$key] ?? null) !== $value) {
            cloudFail(10);
        }
    }
    return $app; // Validation only. No app/config import or activation is done.
}

function cloudPDO(?string $password = null): PDO {
    try {
        return new PDO($password === null ? 'mysql:unix_socket=/var/run/mysql/mysql.sock;charset=utf8mb4'
            : 'mysql:host=127.0.0.1;dbname=nextcloud;charset=utf8mb4',
            $password === null ? 'root' : 'nextcloud', $password,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    } catch (Throwable) {
        cloudFail(26);
    }
}

function cloudDatabaseVersion(array $c, string $actual): void {
    if (!preg_match('/\A([0-9]+(?:\.[0-9]+)+)-MariaDB(?:[-+][A-Za-z0-9.+_~-]+)?\z/', $actual, $version)
        || $version[1] !== $c['versions']['database']) {
        cloudFail(23);
    }
}

function cloudEnsureDatabase(array $c, PDO $db, string $password): void {
    cloudDatabaseVersion($c, (string)$db->query('SELECT VERSION()')->fetchColumn());
    // Account statements never enter general, slow or binary logs. The hash is
    // built only in PHP memory, never in an SQL file, shell variable or argv.
    $db->exec('SET SESSION sql_log_bin=0');
    $db->exec('SET SESSION sql_log_off=1');
    $db->exec('SET SESSION long_query_time=31536000');
    $verifier = '*' . strtoupper(sha1(sha1($password, true)));
    $account = $db->query("SELECT plugin, authentication_string FROM mysql.user WHERE User='nextcloud' AND Host='127.0.0.1'")->fetch(PDO::FETCH_ASSOC);
    if ($account !== false && ($account['plugin'] !== 'mysql_native_password'
        || !hash_equals($verifier, $account['authentication_string']))) {
        cloudFail(23);
    }
    if ($account !== false) {
        foreach ($db->query("SHOW GRANTS FOR 'nextcloud'@'127.0.0.1'")->fetchAll(PDO::FETCH_COLUMN) as $grant) {
            // SHOW GRANTS can include the verifier: examine it only in memory.
            if (str_contains($grant, 'WITH GRANT OPTION')
                || (!str_starts_with($grant, 'GRANT USAGE ON *.* TO ')
                    && !str_contains($grant, ' ON `nextcloud`.* TO '))) {
                cloudFail(23);
            }
        }
    }
    $db->exec('CREATE DATABASE IF NOT EXISTS `nextcloud` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin');
    if ($db->query("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='nextcloud'")->fetchColumn() !== 'utf8mb4_bin') {
        cloudFail(23);
    }
    $db->exec("CREATE USER IF NOT EXISTS 'nextcloud'@'127.0.0.1' IDENTIFIED VIA mysql_native_password USING '$verifier'");
    // ALTER is safe only after existing credentials have matched above.
    $db->exec("ALTER USER 'nextcloud'@'127.0.0.1' IDENTIFIED VIA mysql_native_password USING '$verifier'");
    $db->exec("GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES, CREATE TEMPORARY TABLES, LOCK TABLES ON `nextcloud`.* TO 'nextcloud'@'127.0.0.1'");
    $db->exec("ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket");
    foreach ($db->query("SELECT User, Host FROM mysql.user WHERE User='' OR (User='root' AND Host <> 'localhost')")->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $db->exec('DROP USER IF EXISTS ' . $db->quote($row['User']) . '@' . $db->quote($row['Host']));
    }
}

function cloudDatabase(array $c, array $secret): void {
    if (posix_geteuid() !== 0) {
        cloudFail(11);
    }
    cloudEnsureDatabase($c, cloudPDO(), $secret['db_password']);
    cloudPDO($secret['db_password'])->query('SELECT 1');
}

function cloudWWW(): void {
    $www = posix_getpwnam('www');
    if ($www === false || posix_geteuid() !== $www['uid']) {
        cloudFail(11);
    }
}

function cloudSelectedCodeVersion(array $c, mixed $version): bool {
    return is_string($version) && preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z/', $version)
        && implode('.', array_slice(explode('.', $version), 0, 3)) === $c['versions']['nextcloud'];
}

function cloudCode(array $c, string $path = CLOUD_APP): string {
    foreach (['version.php', 'occ', '.htaccess', 'lib/base.php', '3rdparty/autoload.php', 'core/signature.json'] as $file) {
        if (!is_file($path . '/' . $file) || is_link($path . '/' . $file)) {
            cloudFail(12);
        }
    }
    // Do not execute application code as root just to identify its version.
    $source = file_get_contents($path . '/version.php', false, null, 0, 65537);
    if ($source === false || strlen($source) > 65536
        || preg_match_all('~\$OC_VersionString\s*=\s*([\'"])([0-9]+\.[0-9]+\.[0-9]+)\1\s*;~', $source, $public, PREG_SET_ORDER) !== 1
        || $public[0][2] !== $c['versions']['nextcloud']) {
        cloudFail(12); // Internal build tuples alone cannot distinguish an RC.
    }
    if (preg_match_all('/\$OC_Version\s*=\s*(?:array\s*\(|\[)\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*(?:\)|\])\s*;/', $source, $matches, PREG_SET_ORDER) !== 1) {
        cloudFail(12);
    }
    $version = implode('.', array_slice($matches[0], 1));
    if (!cloudSelectedCodeVersion($c, $version)) {
        cloudFail(12);
    }
    return $version;
}

function cloudAppConfig(): array {
    cloudWWW();
    $file = CLOUD_APP . '/config/config.php';
    if (!file_exists($file)) {
        return [];
    }
    if (is_link($file) || !is_file($file) || glob(CLOUD_APP . '/config/*.config.php')) {
        cloudFail(21);
    }
    $CONFIG = [];
    try {
        require $file;
    } catch (Throwable) {
        cloudFail(20);
    }
    if (!is_array($CONFIG)) {
        cloudFail(21);
    }
    return $CONFIG;
}

// Pure decision function: a failed migration is NOT resumed by rerunning setup.
// A host app/data/database checkpoint is the explicit recovery boundary.
function cloudInstallDecision(array $c, array $app, int $tables, array $dataEntries, bool $admin): string {
    if ($app !== [] && ($app['cloud_installer_identity'] ?? '') !== cloudIdentity($c)) {
        cloudFail(21);
    }
    if (($app['installed'] ?? false) === true) {
        if (($app['maintenance'] ?? false) !== false || !cloudSelectedCodeVersion($c, $app['version'] ?? null)) {
            cloudFail(22);
        }
        if ($tables === 0 || !$admin || !in_array('.ncdata', $dataEntries, true)
            || ($app['dbname'] ?? '') !== 'nextcloud' || ($app['dbuser'] ?? '') !== 'nextcloud'
            || ($app['dbhost'] ?? '') !== '127.0.0.1' || ($app['dbtype'] ?? '') !== 'mysql'
            || ($app['dbtableprefix'] ?? '') !== 'oc_' || ($app['datadirectory'] ?? '') !== '/var/nc-data'
            || ($app['overwrite.cli.url'] ?? '') !== $c['public_url']
            || !in_array(cloudAuthority($c), $app['trusted_domains'] ?? [], true)
            || !cloudString($app['instanceid'] ?? null, 1)) {
            cloudFail(21);
        }
        return 'installed';
    }
    // Setup's environment check creates only these two data-protection files
    // before migrations. Keep them, and all generated config values, on retry.
    $allowed = $app === [] ? [] : ['.htaccess', 'index.html'];
    if ($tables !== 0 || array_diff($dataEntries, $allowed)) {
        cloudFail(20);
    }
    return 'fresh';
}

function cloudInspect(array $c, array $app, PDO $db): string {
    cloudDatabaseVersion($c, (string)$db->query('SELECT VERSION()')->fetchColumn());
    $tables = (int)$db->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='nextcloud'")->fetchColumn();
    $admin = false;
    if (($app['installed'] ?? false) === true) {
        try {
            $query = $db->prepare("SELECT COUNT(*) FROM oc_users u INNER JOIN oc_group_user g ON g.uid=u.uid WHERE u.uid=? AND g.gid='admin'");
            $query->execute([$c['admin_username']]);
            $admin = (int)$query->fetchColumn() === 1;
            $admin = $admin && $db->query("SELECT configvalue FROM oc_appconfig WHERE appid='core' AND configkey='installedat'")->fetchColumn() !== false;
        } catch (Throwable) {
            cloudFail(20);
        }
    }
    $entries = scandir('/var/nc-data');
    if ($entries === false) {
        cloudFail(21);
    }
    return cloudInstallDecision($c, $app, $tables, array_values(array_diff($entries, ['.', '..', '.zfs'])), $admin);
}

function cloudInstalled(array $c): void {
    $version = cloudCode($c);
    $app = cloudAppConfig();
    if (($app['installed'] ?? false) === true && ($app['version'] ?? '') !== $version) {
        cloudFail(22);
    }
    if (!cloudString($app['dbpassword'] ?? null, 1)
        || cloudInspect($c, $app, cloudPDO($app['dbpassword'])) !== 'installed') {
        cloudFail(20);
    }
}

function cloudCheckpointState(bool $configured, int $tables, array $dataEntries): void {
    if ($configured || $tables !== 0 || $dataEntries !== []) {
        cloudFail(28);
    }
}

function cloudCheckpointReady(array $c, array $secret): void {
    cloudWWW();
    cloudCode($c);
    $config = CLOUD_APP . '/config/config.php';
    $configured = file_exists($config) || is_link($config) || (bool)glob(CLOUD_APP . '/config/*.config.php');
    // Do not bootstrap Nextcloud here: that could create protection files or
    // other application state. PDO only reads metadata; no SQL/auth data prints.
    $db = cloudPDO($secret['db_password']);
    cloudDatabaseVersion($c, (string)$db->query('SELECT VERSION()')->fetchColumn());
    $tables = (int)$db->query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='nextcloud'")->fetchColumn();
    $entries = scandir('/var/nc-data');
    if ($entries === false) {
        cloudFail(28);
    }
    cloudCheckpointState($configured, $tables, array_values(array_diff($entries, ['.', '..', '.zfs'])));
}

function cloudBoot(array $c, string $command): void {
    cloudWWW();
    if (!chdir(CLOUD_APP)) {
        cloudFail(12);
    }
    // ConsoleEvent and profiler argv are credential-free, too.
    $GLOBALS['argv'] = $_SERVER['argv'] = [CLOUD_APP . '/occ', $command];
    $_SERVER['argc'] = 2;
    $_SERVER['SCRIPT_FILENAME'] = $_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = CLOUD_APP . '/occ';
    $_SERVER['HTTP_HOST'] = cloudAuthority($c);
    $_SERVER['SERVER_NAME'] = $c['public_hostname'];
    $_SERVER['HTTPS'] = 'on';
    define('OC_CONSOLE', 1);
    require CLOUD_APP . '/lib/versioncheck.php';
    require CLOUD_APP . '/lib/base.php';
    set_time_limit(0);
}

function cloudInstall(array $c, array $secret): void {
    cloudWWW();
    cloudCode($c);
    $app = cloudAppConfig();
    $db = cloudPDO($secret['db_password']);
    if (cloudInspect($c, $app, $db) === 'installed') {
        if (!hash_equals($app['dbpassword'] ?? '', $secret['db_password'])) {
            cloudFail(21);
        }
        cloudInstalled($c);
        return;
    }
    umask(0077);
    $initial = array_replace($app, cloudSystemConfig($c), [
        'installed' => false, 'cloud_installer_identity' => cloudIdentity($c),
        // Setup can log SQL and raw exception context. Only our fixed error
        // categories go to the private phase log; publish restores production logging.
        'logfile' => '/dev/null', 'loglevel' => 4,
    ]);
    $file = CLOUD_APP . '/config/config.php';
    if (file_put_contents($file, "<?php\n\$CONFIG = " . var_export($initial, true) . ";\n", LOCK_EX) === false) {
        cloudFail(27);
    }
    cloudBoot($c, 'maintenance:install');
    $input = new Symfony\Component\Console\Input\ArrayInput([
        'command' => 'maintenance:install', '--no-interaction' => true,
        '--database' => 'mysql', '--database-name' => 'nextcloud',
        '--database-user' => 'nextcloud', '--database-host' => '127.0.0.1',
        '--database-pass' => $secret['db_password'], '--admin-user' => $c['admin_username'],
        // Setup::install HTML-decodes even CLI passwords.
        '--admin-pass' => htmlspecialchars($secret['admin_password'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        '--admin-email' => $c['admin_email'], '--data-dir' => '/var/nc-data',
    ]);
    $input->setInteractive(false);
    // loadCommands requires ConsoleOutputInterface. Drop all upstream output,
    // including exception rendering on its separate error stream.
    $output = new class extends Symfony\Component\Console\Output\ConsoleOutput {
        protected function doWrite(string $message, bool $newline): void {}
    };
    $output->setErrorOutput(new Symfony\Component\Console\Output\NullOutput());
    $application = OCP\Server::get(OC\Console\Application::class);
    // Nextcloud binds only global options while loading commands. Modern
    // Symfony rejects command-specific ArrayInput options at that point; pass
    // credentials only to run(), after maintenance:install is registered.
    $registration = new Symfony\Component\Console\Input\ArrayInput([]);
    $registration->setInteractive(false);
    $application->loadCommands($registration, $output);
    $application->setAutoExit(false);
    if ($application->run($input, $output) !== 0) {
        cloudFail(24);
    }
    cloudInstalled($c);
}

function cloudMimetypeRepair(array $c): void {
    cloudInstalled($c); // Includes the immutable selected code/build and identity checks.
    cloudBoot($c, 'mimetype-repair');
    if (OCP\Util::needUpgrade()) {
        cloudFail(22);
    }
    // Reviewed 2026-10-15: nextcloud/server v35.0.0 and v35.0.1,
    // lib/private/Repair/RepairMimeTypes.php and Migration/NullOutput.php.
    // run() alone owns the final files/mimetype_version write. Do not invoke
    // maintenance:repair's unrelated enabled-app hooks or fake that version.
    $repair = OCP\Server::get(OC\Repair\RepairMimeTypes::class);
    $repair->run(new OC\Migration\NullOutput());
    // Check only AFTER run: the native dry run retains a change counter.
    if ($repair->migrationsAvailable()) {
        cloudFail(30);
    }
}

function cloudConnectorId(array $c): string {
    $backend = $c['versions']['office_backend'] ?? 'onlyoffice';
    $ids = ['onlyoffice' => 'onlyoffice', 'eurooffice' => 'eurooffice', 'collabora' => 'richdocuments'];
    if (!isset($ids[$backend])
        || ($backend !== 'onlyoffice' && ($c['versions']['connector_app'] ?? null) !== $ids[$backend])) {
        cloudFail(10);
    }
    return $ids[$backend];
}

function cloudConnectorVersion(array $c, mixed $info): void {
    if (!is_array($info) || ($info['id'] ?? '') !== cloudConnectorId($c)
        || ($info['version'] ?? '') !== $c['versions']['connector']) {
        cloudFail(25);
    }
}

function cloudConnectorCertificate(mixed $value): string {
    if (!is_string($value) || strlen($value) > 16384
        || !preg_match('~\A-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----(?:\r?\n)?\z~', $value, $match)) {
        cloudFail(29);
    }
    $encoded = str_replace(["\r", "\n"], '', $match[1]);
    $decoded = base64_decode($encoded, true);
    if ($decoded === false || $decoded === '' || base64_encode($decoded) !== $encoded) {
        cloudFail(29);
    }
    return $decoded; // Shape/identity only; the native installer/checker verifies X.509 trust.
}

function cloudConnectorRecord(array $c, string $input): array {
    $app = cloudConnectorId($c);
    if (strlen($input) > 65536 || !hash_equals($c['versions']['connector_sha256'], hash('sha256', $input))) {
        cloudFail(29);
    }
    $record = cloudDecode($input);
    $keys = ['version', 'phpVersionSpec', 'platformVersionSpec', 'isNightly',
        'signatureDigest', 'download', 'signature', 'certificate'];
    if (array_diff(array_keys($record), $keys) || array_diff($keys, array_keys($record))
        || $record['version'] !== $c['versions']['connector'] || $record['isNightly'] !== false
        || $record['signatureDigest'] !== 'sha512') {
        cloudFail(29);
    }
    foreach (['phpVersionSpec', 'platformVersionSpec'] as $key) {
        $pattern = '/\A>=[0-9]+\.[0-9]+\.[0-9]+ +<[0-9]+\.[0-9]+\.[0-9]+\z/';
        if ($app !== 'onlyoffice' && $key === 'phpVersionSpec') {
            // Preserve the literal VM manifest declaration, not a fabricated
            // ceiling. The host policy and native app dependency check enforce
            // the selected PHP runtime independently.
            $pattern = '/\A(?:\*|>=[0-9]+\.[0-9]+\.[0-9]+(?: +<[0-9]+\.[0-9]+\.[0-9]+)?)\z/';
        }
        if (!cloudString($record[$key], 1, 128) || !preg_match($pattern, $record[$key])) {
            cloudFail(29);
        }
    }
    if (!cloudString($record['download'], 1, 4096) || preg_match('/[\s\\\\]/', $record['download'])
        || !filter_var($record['download'], FILTER_VALIDATE_URL)) {
        cloudFail(29);
    }
    $url = parse_url($record['download']);
    if ($url === false || ($url['scheme'] ?? '') !== 'https' || empty($url['host'])
        || isset($url['user']) || isset($url['pass']) || isset($url['fragment'])) {
        cloudFail(29);
    }
    // The authoritative app-store API folds base64 signatures across lines.
    // Validate a canonical unfolded representation, but retain the signed record
    // bytes unchanged for its hash and the native installer's verification.
    if (!is_string($record['signature']) || strlen($record['signature']) > 16384
        || !preg_match('~\A[A-Za-z0-9+/=\r\n]+\z~', $record['signature'])) {
        cloudFail(29);
    }
    $encoded = str_replace(["\r", "\n"], '', $record['signature']);
    if (!preg_match('~\A[A-Za-z0-9+/]+={0,2}\z~', $encoded)
        || ($signature = base64_decode($encoded, true)) === false
        || base64_encode($signature) !== $encoded) {
        cloudFail(29);
    }
    cloudConnectorCertificate($record['certificate']);
    return $record;
}

function cloudConnectorRead(array $c): array {
    if (!in_array($c['versions']['office_backend'] ?? 'onlyoffice', ['onlyoffice', 'eurooffice', 'collabora'], true)) {
        cloudFail(10);
    }
    $stream = fopen('php://fd/4', 'rb');
    if ($stream === false) {
        cloudFail(29);
    }
    try {
        $stat = fstat($stream);
        if ($stat === false || $stat['uid'] !== 0 || ($stat['mode'] & 0170000) !== 0100000
            || !in_array($stat['mode'] & 0777, [0400, 0600], true) || $stat['size'] > 65536) {
            cloudFail(29);
        }
        $input = stream_get_contents($stream, 65537);
        if ($input === false) {
            cloudFail(29);
        }
        return cloudConnectorRecord($c, $input);
    } finally {
        fclose($stream);
    }
}

function cloudConnectorInstaller(array $record, string $app = 'onlyoffice'): OC\Installer {
    if (!in_array($app, ['onlyoffice', 'eurooffice', 'richdocuments'], true)) {
        cloudFail(10);
    }
    // v35.0.1 AppFetcher::get is the only fetcher API used by downloadApp.
    // Supply exactly the retained release; never consult mutable releases[0].
    $fetcher = new class($record, $app) extends OC\App\AppStore\Fetcher\AppFetcher {
        public function __construct(private array $record, private string $app) {}
        public function get($allowUnstable = false): array {
            if ($allowUnstable !== false) {
                cloudFail(29);
            }
            return [['id' => $this->app, 'certificate' => $this->record['certificate'],
                'releases' => [$this->record]]];
        }
    };
    // Retain native CA/CRL/CN, SHA512 archive verification and dependency checks.
    // No reflection, container replacement or custom archive installation.
    return new OC\Installer($fetcher,
        OCP\Server::get(OCP\Http\Client\IClientService::class), OCP\Server::get(OCP\ITempManager::class),
        OCP\Server::get(Psr\Log\LoggerInterface::class), OCP\Server::get(OCP\IConfig::class),
        OCP\Server::get(OC\App\AppManager::class), OCP\Server::get(OCP\L10N\IFactory::class), true);
}

function cloudConnectorTree(array $record, string $path, object $checker, string $app = 'onlyoffice'): string {
    if (!in_array($app, ['onlyoffice', 'eurooffice', 'richdocuments'], true)) {
        cloudFail(10);
    }
    if (!is_dir($path) || is_link($path) || !is_dir($path . '/appinfo') || is_link($path . '/appinfo')) {
        cloudFail(29);
    }
    // Native traversal must never follow a link or block on a special file.
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($files as $file) {
        if ($file->isLink() || (!$file->isDir() && !$file->isFile())) {
            cloudFail(29);
        }
    }
    $manifest = $path . '/appinfo/signature.json';
    if (!is_file($manifest) || is_link($manifest) || filesize($manifest) > 1048576) {
        cloudFail(29);
    }
    $bytes = file_get_contents($manifest, false, null, 0, 1048577);
    if ($bytes === false || strlen($bytes) > 1048576) {
        cloudFail(29);
    }
    $signature = json_decode($bytes, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($signature) || !is_array($signature['hashes'] ?? null)
        || !isset($signature['hashes']['appinfo/info.xml'])
        || !hash_equals(cloudConnectorCertificate($record['certificate']), cloudConnectorCertificate($signature['certificate'] ?? null))) {
        cloudFail(29);
    }
    $digest = hash('sha256', $bytes);
    if ($checker->verifyAppSignature($app, $path, true) !== []
        || hash_file('sha256', $manifest) !== $digest) {
        cloudFail(29);
    }
    return $digest;
}

function cloudConnectorApply(array $c, array $record, string $path, object $installer,
    object $manager, object $config, object $checker): void {
    $app = cloudConnectorId($c);
    if (basename($path) !== $app) {
        cloudFail(29);
    }
    $key = 'cloud_installer_connector_auth';
    $receipt = $config->getSystemValue($key, null);
    $exists = file_exists($path) || is_link($path);
    // AppConfig::getAppInstalledVersions caches its first result for the process.
    // Use the direct value API, as native installApp/enableApp do, across writes.
    $installed = $config->getAppValue($app, 'installed_version', '');
    if ($installed !== '' && $installed !== $c['versions']['connector']) {
        cloudFail(25);
    }
    if ($exists) {
        // A directory/info.xml is not proof that downloadApp finished its copy.
        if (!is_array($receipt) || count($receipt) !== 2
            || ($receipt['record_sha256'] ?? null) !== $c['versions']['connector_sha256']
            || !cloudString($receipt['manifest_sha256'] ?? null, 64, 64)
            || !preg_match('/\A[a-f0-9]{64}\z/', $receipt['manifest_sha256'])) {
            cloudFail(29);
        }
    } else {
        if ($receipt !== null || $installed !== '' || $installer->getInstallPath() !== dirname($path)) {
            cloudFail(29);
        }
        // Never overwrite an existing tree, even one left by an interrupted copy.
        $installer->downloadApp($app, false);
    }
    $manifest = cloudConnectorTree($record, $path, $checker, $app);
    if ($exists && !hash_equals($receipt['manifest_sha256'], $manifest)) {
        cloudFail(29);
    }
    if ($manager->getAppPath($app, true) !== $path) {
        cloudFail(25);
    }
    $manager->clearAppsCache();
    $info = $manager->getAppInfo($app);
    cloudConnectorVersion($c, $info);
    if (!$manager->isAppCompatible($c['versions']['nextcloud'], $info, false)) {
        cloudFail(25);
    }
    $manager->checkAppDependencies($app, false);
    if (!$exists) {
        // Durable public evidence outside the signed tree, written only after
        // native archive authentication AND complete per-file verification.
        $receipt = ['record_sha256' => $c['versions']['connector_sha256'], 'manifest_sha256' => $manifest];
        $config->setSystemValue($key, $receipt);
        if ($config->getSystemValue($key, null) !== $receipt) {
            cloudFail(29);
        }
    }
    if ($installed === '' && $installer->installApp($app, false) !== $app) {
        cloudFail(25);
    }
    if ($config->getAppValue($app, 'installed_version', '') !== $c['versions']['connector']) {
        cloudFail(25);
    }
    if (!$manager->isEnabledForAnyone($app)) {
        $manager->enableApp($app, false);
    }
}

function cloudConnectorInstall(array $c): void {
    $record = cloudConnectorRead($c); // Authenticate public fd4 bytes before application code.
    $app = cloudConnectorId($c);
    cloudInstalled($c);
    cloudBoot($c, 'app:install');
    if (OCP\Util::needUpgrade()) {
        cloudFail(22);
    }
    cloudConnectorApply($c, $record, CLOUD_APP . '/custom_apps/' . $app, cloudConnectorInstaller($record, $app),
        OCP\Server::get(OCP\App\IAppManager::class), OCP\Server::get(OCP\IConfig::class),
        OCP\Server::get(OC\IntegrityCheck\Checker::class));
}

function cloudConnectorImport(array $c, array $connector): void {
    $backend = $c['versions']['office_backend'] ?? 'onlyoffice';
    if (!in_array($backend, ['onlyoffice', 'eurooffice', 'collabora'], true)) {
        cloudFail(10);
    }
    $settings = $backend !== 'onlyoffice' ? cloudVmConnector($connector, $c) : cloudConnector($connector, $c);
    $app = cloudConnectorId($c);
    cloudInstalled($c);
    cloudBoot($c, 'config:import');
    if (OCP\Util::needUpgrade()) {
        cloudFail(22);
    }
    $manager = OCP\Server::get(OCP\App\IAppManager::class);
    $info = $manager->getAppInfo($app);
    cloudConnectorVersion($c, $info);
    if (!$info || !$manager->isEnabledForAnyone($app)
        || !$manager->isAppCompatible(implode('.', OCP\Util::getVersion()), $info)) {
        cloudFail(25);
    }
    // Supported NC35 API, equivalent to apps-only config:import. Unlike an
    // import followed by --sensitive, the JWT is encrypted on its FIRST write,
    // so no plaintext JWT reaches MariaDB's row binlog or the appconfig table.
    $config = OCP\Server::get(OCP\IAppConfig::class);
    foreach ($settings as $key => $value) {
        $config->setValueString($app, $key, $value, false, $key === 'jwt_secret');
    }
    if ($backend !== 'collabora' && !$config->isSensitive($app, 'jwt_secret')) {
        cloudFail(25);
    }
}

function cloudMain(array $args): int {
    $buffer = ob_get_level();
    try {
        if (PHP_SAPI !== 'cli') {
            cloudFail(11);
        }
        $mode = $args[1] ?? '';
        $secretPhase = in_array($mode, ['database', 'checkpoint-ready', 'install', 'connector-import'], true);
        if ($secretPhase || in_array($mode, ['installed-check', 'mimetype-repair', 'connector-install'], true)) {
            ini_set('log_errors', '0');
            ini_set('error_log', '/dev/null');
            ini_set('display_errors', '0');
            ini_set('zend.exception_ignore_args', '1');
            ob_start(static fn (string $text): string => '', 8192);
        }
        // mdo(1) on FreeBSD 15.1 retains inherited descriptors (usr.bin/mdo/mdo.c).
        $public = fopen(posix_geteuid() === 0 ? CLOUD_RUNTIME : 'php://fd/3', 'rb');
        if ($public === false) {
            cloudFail(10);
        }
        $c = cloudValidate(cloudRead($public));
        fclose($public);
        cloudPHPEnvironment($c);
        switch ($mode) {
            case 'validate': break;
            case 'get':
                if (!in_array($args[2] ?? '', ['repository', 'tls_mode', 'public_hostname', 'public_url', 'storage_url', 'onlyoffice_ip', 'acme_email'], true)
                    || !array_key_exists($args[2], $c)) {
                    cloudFail(10);
                }
                echo $c[$args[2]], "\n";
                break;
            case 'apps': echo implode("\n", cloudApps($c['nextcloud_apps'] ?? '')); break;
            case 'app-state':
                echo cloudOptionalAppState($args[2] ?? '',
                    json_decode(file_get_contents($args[3]), true, 32, JSON_THROW_ON_ERROR),
                    file_get_contents($args[4])), "\n";
                break;
            case 'render': echo cloudRender(file_get_contents($args[2]), $c); break;
            case 'patch-ini': echo cloudPatchIni(file_get_contents($args[3]), cloudRender(file_get_contents($args[2]), $c)); break;
            case 'system-config': echo json_encode(['system' => cloudSystemConfig($c)], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\n"; break;
            case 'code-check': cloudCode($c); break;
            case 'installed-check': cloudInstalled($c); break;
            case 'mimetype-repair': cloudMimetypeRepair($c); break;
            case 'database': cloudDatabase($c, cloudSecrets(cloudRead(STDIN), 'database')); break;
            case 'checkpoint-ready': cloudCheckpointReady($c, cloudSecrets(cloudRead(STDIN), 'checkpoint-ready')); break;
            case 'install': cloudInstall($c, cloudSecrets(cloudRead(STDIN), 'install')); break;
            case 'connector-install': cloudConnectorInstall($c); break;
            case 'connector-import': cloudConnectorImport($c, cloudRead(STDIN)); break;
            default: cloudFail(10);
        }
        return 0;
    } catch (Throwable $error) {
        fwrite(STDERR, cloudDiagnostic($error) . "\n");
        return 1;
    } finally {
        while (ob_get_level() > $buffer) {
            ob_end_clean();
        }
    }
}

if (!defined('CLOUD_NEXTCLOUD_LIBRARY')) {
    exit(cloudMain($argv));
}
