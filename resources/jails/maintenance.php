<?php
declare(strict_types=1);

/* Internal CLI worker, installed root:www 0640 outside the web root.
 * Host root opens stdin before mdo drops to www. No credential is an argv
 * value or an inherited process environment setting. See NC35's console.php,
 * lib/private/Console/Application.php and core/Command/User/Add.php.
 */

function cloudOperationsUser(array $value): array {
    if (array_diff(array_keys($value), ['username', 'password', 'display_name', 'email'])) {
        throw new RuntimeException('Unexpected account fields.');
    }
    foreach (['username', 'password', 'display_name', 'email'] as $key) {
        if (!isset($value[$key]) || !is_string($value[$key])
            || preg_match('/[\x00-\x1f\x7f]/', $value[$key])) {
            throw new RuntimeException('Invalid account field.');
        }
    }
    if (!preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/', $value['username'])) {
        throw new RuntimeException('Invalid username.');
    }
    $length = preg_match_all('/./us', $value['password']);
    if ($length === false || $length < 14 || $length > 1024
        || strlen($value['display_name']) > 1016 || strlen($value['email']) > 254) {
        throw new RuntimeException('Invalid account detail length.');
    }
    if ($value['email'] !== '' && (!filter_var($value['email'], FILTER_VALIDATE_EMAIL)
        || !preg_match('/\A[A-Za-z0-9_+%.\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\z/', $value['email']))) {
        throw new RuntimeException('Invalid email.');
    }
    return $value;
}

function cloudOperationsBootstrap(): void {
    $app = '/usr/local/www/nextcloud';
    $www = posix_getpwnam('www');
    if (PHP_SAPI !== 'cli' || $www === false || posix_geteuid() !== $www['uid']
        || fileowner($app . '/config/config.php') !== $www['uid'] || !chdir($app)) {
        throw new RuntimeException('Run the installed helper as www.');
    }
    umask(0077);
    ini_set('display_errors', '0');
    ini_set('log_errors', '0');
    ini_set('zend.exception_ignore_args', '1');
    // Keep ConsoleEvent/profiling metadata free of the stdin account payload.
    $GLOBALS['argv'] = $_SERVER['argv'] = [$app . '/occ'];
    $_SERVER['argc'] = 1;
    $_SERVER['SCRIPT_FILENAME'] = $_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = $app . '/occ';
    define('OC_CONSOLE', 1);
    require $app . '/lib/versioncheck.php';
    require $app . '/lib/base.php';
    set_time_limit(0);
    if (!OCP\Server::get(OCP\IConfig::class)->getSystemValueBool('installed', false)) {
        throw new RuntimeException('Nextcloud is not installed.');
    }
}

function cloudOperationsMetadata(): array {
    $config = OCP\Server::get(OCP\IConfig::class);
    if ($config->getSystemValueString('dbtype') !== 'mysql'
        || $config->getSystemValueString('dbname') !== 'nextcloud'
        || $config->getSystemValueString('datadirectory') !== '/var/nc-data') {
        throw new RuntimeException('Unexpected managed application layout.');
    }
    $binding = [];
    // Restoring an old config must not silently change the database password,
    // instance encryption identity or managed data path. Return only a digest.
    foreach (['instanceid', 'secret', 'passwordsalt', 'dbpassword', 'dbtype',
        'dbname', 'dbuser', 'dbhost', 'datadirectory'] as $key) {
        $binding[$key] = $config->getSystemValueString($key);
        if ($binding[$key] === '') {
            throw new RuntimeException('Incomplete runtime configuration.');
        }
    }
    $binding['onlyoffice_jwt'] = $config->getAppValue('onlyoffice', 'jwt_secret', '');
    if ($binding['onlyoffice_jwt'] === '') {
        throw new RuntimeException('Missing document integration identity.');
    }
    return [
        'instance_id' => $binding['instanceid'],
        'table_prefix' => $config->getSystemValueString('dbtableprefix', 'oc_'),
        'runtime_binding' => hash('sha256', json_encode($binding, JSON_THROW_ON_ERROR)),
    ];
}

function cloudOperationsCreate(array $value): array {
    if (OCP\Server::get(OCP\IConfig::class)->getSystemValueBool('maintenance', false)) {
        throw new RuntimeException('Cannot add a user during maintenance.');
    }
    $options = ['command' => 'user:add', 'uid' => $value['username'],
        '--password-from-env' => true, '--no-interaction' => true, '--quiet' => true];
    foreach (['display_name' => '--display-name', 'email' => '--email'] as $key => $option) {
        if ($value[$key] !== '') {
            $options[$option] = $value[$key];
        }
    }
    $input = new Symfony\Component\Console\Input\ArrayInput($options);
    $input->setInteractive(false);
    // loadCommands requires ConsoleOutputInterface. Drop all upstream output,
    // including exception rendering on its separate error stream.
    $output = new class extends Symfony\Component\Console\Output\ConsoleOutput {
        protected function doWrite(string $message, bool $newline): void {}
    };
    $output->setErrorOutput(new Symfony\Component\Console\Output\NullOutput());
    $application = OCP\Server::get(OC\Console\Application::class);
    // NC35 binds only global options during registration. Command-specific
    // ArrayInput options belong to run(), once user:add has been registered.
    $registration = new Symfony\Component\Console\Input\ArrayInput([]);
    $registration->setInteractive(false);
    $application->loadCommands($registration, $output);
    $application->setAutoExit(false);
    putenv('NC_PASS');
    putenv('OC_PASS=' . $value['password']);
    unset($value['password']);
    try {
        $code = $application->run($input, $output);
    } finally {
        putenv('OC_PASS');
        unset($_ENV['OC_PASS'], $_SERVER['OC_PASS'], $_ENV['NC_PASS'], $_SERVER['NC_PASS']);
    }
    if ($code !== 0 || !OCP\Server::get(OCP\IUserManager::class)->userExists($value['username'])
        || OCP\Server::get(OCP\IGroupManager::class)->isAdmin($value['username'])) {
        throw new RuntimeException('Could not verify normal user creation.');
    }
    return ['created' => $value['username'], 'admin' => false];
}

function cloudOperationsMain(array $args): int {
    ob_start();
    try {
        if (PHP_SAPI !== 'cli' || count($args) !== 2 || !in_array($args[1], ['metadata', 'create-user'], true)) {
            throw new RuntimeException('Invalid helper mode.');
        }
        $value = null;
        if ($args[1] === 'create-user') {
            $raw = stream_get_contents(STDIN, 16385);
            if ($raw === false || strlen($raw) > 16384) {
                throw new RuntimeException('Input exceeds limit.');
            }
            $value = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
            unset($raw);
            if (!is_array($value) || array_is_list($value)) {
                throw new RuntimeException('Expected JSON account object.');
            }
            $value = cloudOperationsUser($value);
        }
        cloudOperationsBootstrap();
        $result = $args[1] === 'metadata' ? cloudOperationsMetadata() : cloudOperationsCreate($value);
        ob_end_clean();
        echo json_encode($result, JSON_THROW_ON_ERROR), "\n";
        return 0;
    } catch (Throwable $error) {
        ob_end_clean();
        // No exception text, input, stack trace, password, or user details.
        fwrite(STDERR, "Nextcloud maintenance helper failed validation or execution.\n");
        return 1;
    }
}

if (!defined('CLOUD_OPERATIONS_LIBRARY')) {
    exit(cloudOperationsMain($argv));
}
