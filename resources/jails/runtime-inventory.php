<?php
/** Read-only runtime observations. No Nextcloud bootstrap, config, secrets or phpinfo. */
declare(strict_types=1);

function inventory(): array {
    $modules = array_values(array_unique(array_map('strtolower', array_merge(
        get_loaded_extensions(), get_loaded_extensions(true)
    ))));
    sort($modules, SORT_STRING);
    return ['version' => PHP_VERSION, 'sapi' => PHP_SAPI,
            'integer_size' => PHP_INT_SIZE, 'loaded_modules' => $modules];
}

function failProbe(): never {
    if (PHP_SAPI !== 'cli') {
        http_response_code(404);
    } else {
        fwrite(STDERR, "Runtime inventory failed; no environment/configuration diagnostics emitted.\n");
    }
    exit(1);
}

function exactRead($socket, int $size): string {
    $result = '';
    while (strlen($result) < $size) {
        $chunk = fread($socket, $size - strlen($result));
        if ($chunk === false || $chunk === '' || stream_get_meta_data($socket)['timed_out']) {
            throw new RuntimeException('Incomplete FastCGI observation');
        }
        $result .= $chunk;
    }
    return $result;
}

function record(int $type, string $body): string {
    return pack('CCnnCC', 1, $type, 1, strlen($body), 0, 0) . $body;
}

function fpmInventory(string $pool): array {
    $paths = ['main' => '/var/run/php-fpm/nextcloud.sock',
              'callback' => '/var/run/php-fpm/office-callback.sock'];
    if (!isset($paths[$pool])) {
        throw new RuntimeException('Unsupported pool');
    }
    $nonce = bin2hex(random_bytes(16));
    $socket = @stream_socket_client('unix://' . $paths[$pool], $errno, $error, 10);
    if ($socket === false) {
        throw new RuntimeException('Pool unavailable');
    }
    try {
        stream_set_timeout($socket, 10);
        $params = ['GATEWAY_INTERFACE' => 'CGI/1.1', 'REQUEST_METHOD' => 'GET',
                   'SCRIPT_FILENAME' => __FILE__, 'SCRIPT_NAME' => '/cloud-runtime-inventory.php',
                   'SERVER_PROTOCOL' => 'HTTP/1.1', 'SERVER_NAME' => 'localhost',
                   'SERVER_PORT' => '80', 'REMOTE_ADDR' => '127.0.0.1',
                   'CLOUD_INSTALLER_INVENTORY_NONCE' => $nonce];
        $encoded = '';
        foreach ($params as $key => $value) {
            if (strlen($key) >= 128 || strlen($value) >= 128) {
                throw new RuntimeException('Unexpected probe path');
            }
            $encoded .= chr(strlen($key)) . chr(strlen($value)) . $key . $value;
        }
        $request = record(1, pack('nCxxxxx', 1, 0)) . record(4, $encoded) . record(4, '') . record(5, '');
        while ($request !== '') {
            $written = fwrite($socket, $request);
            if ($written === false || $written === 0) {
                throw new RuntimeException('Incomplete request');
            }
            $request = substr($request, $written);
        }
        $output = '';
        $ended = false;
        for ($i = 0; $i < 128; $i++) {
            $header = unpack('Cversion/Ctype/nid/nlength/Cpadding/Creserved', exactRead($socket, 8));
            if ($header['version'] !== 1 || $header['id'] !== 1 || $header['reserved'] !== 0) {
                throw new RuntimeException('Unexpected FastCGI record');
            }
            $body = exactRead($socket, $header['length']);
            exactRead($socket, $header['padding']);
            if ($header['type'] === 6) {
                $output .= $body;
                if (strlen($output) > 32768) {
                    throw new RuntimeException('Oversized pool observation');
                }
            } elseif ($header['type'] === 7) {
                if ($body !== '') {
                    throw new RuntimeException('Pool diagnostic refused');
                }
            } elseif ($header['type'] === 3) {
                // END_REQUEST has four app-status bytes, one protocol-status
                // byte and three reserved bytes. Native FPM need not zero the
                // unused tail; it is not an application/protocol error status.
                if (strlen($body) !== 8 || substr($body, 0, 5) !== str_repeat("\0", 5)) {
                    throw new RuntimeException('Pool request failed');
                }
                $ended = true;
                break;
            } else {
                throw new RuntimeException('Unexpected FastCGI response');
            }
        }
        $parts = explode("\r\n\r\n", $output, 2);
        if (!$ended || count($parts) !== 2 ||
            preg_match('/^Status:/mi', $parts[0]) && !preg_match('/^Status: 200(?: OK)?\r?$/mi', $parts[0]) ||
            !preg_match('/^Content-Type: application\/json(?:;[^\r\n]*)?\r?$/mi', $parts[0])) {
            throw new RuntimeException('Invalid pool response');
        }
        $result = json_decode($parts[1], true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($result) || array_keys($result) !== ['nonce', 'runtime'] ||
            $result['nonce'] !== $nonce || ($result['runtime']['sapi'] ?? '') !== 'fpm-fcgi') {
            throw new RuntimeException('Unbound pool response');
        }
        return $result['runtime'];
    } finally {
        fclose($socket);
    }
}

try {
    if (PHP_SAPI === 'fpm-fcgi') {
        $nonce = $_SERVER['CLOUD_INSTALLER_INVENTORY_NONCE'] ?? '';
        if (!is_string($nonce) || !preg_match('/\A[a-f0-9]{32}\z/', $nonce) ||
            ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
            failProbe();
        }
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode(['nonce' => $nonce, 'runtime' => inventory()], JSON_THROW_ON_ERROR);
    } elseif (PHP_SAPI === 'cli' && $argc === 2 && $argv[1] === 'cli') {
        echo json_encode(inventory(), JSON_THROW_ON_ERROR), "\n";
    } elseif (PHP_SAPI === 'cli' && $argc === 2 && in_array($argv[1], ['main', 'callback'], true)) {
        echo json_encode(fpmInventory($argv[1]), JSON_THROW_ON_ERROR), "\n";
    } else {
        failProbe();
    }
} catch (Throwable $error) {
    failProbe();
}
