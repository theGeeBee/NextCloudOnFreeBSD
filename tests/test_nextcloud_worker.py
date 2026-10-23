"""Offline checks only: never invoke the jail worker or provision services.

Pure PHP checks require PHP >= 8.1. Isolated shell-phase tests replace every
provisioning command with a stub and write only to private temporary directories.
Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_nextcloud_worker.py -v
"""

import configparser
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


from nextcloud_worker_fixtures import (
    TEMPLATES, WORKER_PATH, WORKER, HELPER, PHP_SOURCE,
    VERSIONS_PATH, VERSIONS_SOURCE, PHP, phase, PREPARE, DATABASE, INSTALL,
    PUBLISH, FINISH, connector_record, connector_record_text, runtime, run_php,
)


def template(name):
    return (TEMPLATES / name).read_text()


def connector_tree(version="10.2.1"):
    files = {
        "appinfo/info.xml": f"<info><id>onlyoffice</id><version>{version}</version></info>",
        "lib/Application.php": '<?php throw new RuntimeException("Fixture app code must not execute");',
    }
    files["appinfo/signature.json"] = json.dumps({
        "hashes": {name: hashlib.sha512(text.encode()).hexdigest() for name, text in files.items()},
        "certificate": connector_record()["certificate"], "signature": "offline native-checker fixture",
    })
    return files


def secrets():
    return {"admin_password": "admin-'\\\"&quot;-$-secret", "db_password": "database-'\\\"&-secret"}


def connector(c):
    return {"apps": {"onlyoffice": {
        "DocumentServerUrl": c["public_url"] + "onlyoffice/",
        "DocumentServerInternalUrl": "http://10.77.0.6:8081/",
        "StorageUrl": c["storage_url"],
        "jwt_secret": "jwt-secret-" + "x" * 64,
        "jwt_header": "AuthorizationJWT",
        "verify_peer_off": "false",
    }}}


class NextcloudWorkerContractTests(unittest.TestCase):
    def test_posix_shell_syntax_without_running_installers(self):
        for path in [WORKER_PATH, VERSIONS_PATH, TEMPLATES / "cloud_php_dirs", TEMPLATES / "certbot-deploy", TEMPLATES / "mysql-flush-logs"]:
            with self.subTest(path=path.name):
                result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_platform_payload_ownership_and_mount_guards(self):
        guards = WORKER.split("prepare() {", 1)[0]
        for expected in ['[ "$#" -eq 1 ]', '"$(id -u)" -eq 0', "security.jail.jailed", "version_load nextcloud", "version_environment", "command -v mdo", "0:600|0:400", '"$PAYLOAD")" = 0:700']:
            self.assertIn(expected, guards)
        self.assertIn("$PAYLOAD/resources/templates/nextcloud", WORKER)
        self.assertIn("$PAYLOAD/resources/jails/nextcloud-bootstrap.php", WORKER)
        for path in ["/var/nc-data", "/var/db/mysql", "/var/log/mysql", "/var/log", "/var/nc-tmp"]:
            self.assertIn(path, guards)
        self.assertNotRegex(WORKER, r"\b(?:zfs|zpool|bastille|mount)\s+(?:create|destroy|mount|jail)")

    def test_maintenance_helper_is_staged_before_first_readiness(self):
        from installer.operations import HELPER
        statement = ('install -o root -g www -m 640 "$PAYLOAD/resources/jails/maintenance.php" ' + HELPER)
        self.assertIn(statement, PREPARE)
        self.assertLess(PREPARE.index(statement), PREPARE.index('touch "$STATE/nextcloud-prepared"'))
        self.assertIn('install -o root -g www -m 640 "$PAYLOAD/resources/jails/runtime-inventory.php"', PREPARE)

    def test_resume_markers_follow_effects_and_no_data_reset(self):
        self.assertIn('if [ ! -d "$STATE/nextcloud-started" ]', phase("initialize_state"))
        self.assertIn("Unowned existing storage", phase("initialize_state"))
        self.assertIn("original immutable configuration", WORKER)
        self.assertIn('if [ -f "$STATE/nextcloud-prepared" ]', PREPARE)
        self.assertLess(PREPARE.index("Nextcloud prepare already complete"), PREPARE.index("pkg bootstrap"))
        for section, operation, marker in [
            (PREPARE, "version_packages_install", 'touch "$STATE/nextcloud-packages"'),
            (PREPARE, "newsyslog -n", 'touch "$STATE/nextcloud-prepared"'),
            (DATABASE, '"$BOOTSTRAP" database', 'touch "$STATE/nextcloud-database"'),
            (INSTALL, "installed_check", 'touch "$STATE/nextcloud-installed"'),
            (PUBLISH, "service apache24 graceful", 'touch "$STATE/nextcloud-published"'),
            (FINISH, "installed_check", 'touch "$STATE/nextcloud-finished"'),
        ]:
            self.assertLess(section.index(operation), section.index(marker))
        self.assertNotIn("restore the fresh jail/datasets before retrying", WORKER)
        self.assertNotIn("DROP DATABASE", PHP_SOURCE)
        for removal in re.findall(r"\brm\s+([^;\n]+)", WORKER):
            self.assertIn("$stage", removal)
            self.assertNotIn("$APP", removal)
            self.assertNotIn("$STATE", removal)

    def test_scoped_package_bootstrap_is_retryable_and_umask_is_correct(self):
        mask = None
        calls = []
        for line in WORKER.splitlines():
            stripped = line.strip()
            if stripped.startswith("umask "):
                mask = stripped.split()[1]
            if stripped.startswith("pkg "):
                calls.append(stripped)
                self.assertEqual(mask, "022")
                self.assertIn("-r FreeBSD-ports", stripped)
                self.assertIn("< /dev/null", stripped)
                self.assertNotIn("upgrade", stripped)
        self.assertTrue(calls)
        self.assertEqual(PREPARE.count('if [ ! -f "$STATE/nextcloud-packages" ]'), 1)
        self.assertLess(PREPARE.index("pkg update"), PREPARE.index("version_packages_install"))
        self.assertLess(PREPARE.index("version_packages_install"), PREPARE.index("stage=$(mktemp"))
        self.assertNotIn("packages.txt", PREPARE)
        self.assertNotRegex(WORKER, r"php85|mariadb123|latest-35|15\.1-\*")
        self.assertIn('if [ "$mode" != prepare ] || [ -f "$STATE/nextcloud-packages" ]; then version_packages_check; fi', WORKER)

    def test_base_parser_precedes_all_state_changes_and_never_evaluates_json(self):
        self.assertIn('require("ucl").parser()', VERSIONS_SOURCE)
        self.assertIn('read -r repository version_nextcloud', VERSIONS_SOURCE)
        self.assertNotRegex(VERSIONS_SOURCE, r"\beval\b")
        self.assertNotIn("repository=$(awk", PREPARE)
        self.assertLess(WORKER.index("version_load nextcloud"), WORKER.index("\ninitialize_state\n"))
        self.assertLess(WORKER.index("version_environment"), WORKER.index("\ninitialize_state\n"))

    def test_release_authentication_and_retained_copy_precede_code_execution(self):
        self.assertIn('archive="nextcloud-${version_nextcloud}.tar.bz2"', PREPARE)
        self.assertNotRegex(PREPARE, r"latest-[0-9]+|archive=latest")
        self.assertIn("28806A878AE423A28372792ED75899B9A724937A", PREPARE)
        self.assertLess(PREPARE.index("--verify"), PREPARE.index("tar -xjf"))
        self.assertLess(PREPARE.index("Archive was not signed"), PREPARE.index("tar -xjf"))
        self.assertIn('if [ ! -f "$STATE/nextcloud-code-ready" ]', PREPARE)
        self.assertIn('if [ ! -f "$STATE/nextcloud-release.sha256" ]', PREPARE)
        self.assertIn("Retained authenticated archive changed", PREPARE)
        self.assertIn("--strip-components 1 --no-same-owner --no-same-permissions", PREPARE)
        self.assertNotIn('"$HELPER" install', PREPARE)

    def test_credentials_have_only_stdin_routes_and_no_combined_document(self):
        for forbidden in ["secrets.json", "database.sql", "--admin-pass=", "--database-pass=", "DB_PASSWORD", "ADMIN_PASSWORD", "MYSQL_PWD", "set -x", "json sql"]:
            self.assertNotIn(forbidden, WORKER)
        self.assertIn('"$HELPER" install 3< "$RUNTIME"', INSTALL)
        self.assertIn('"$HELPER" connector-import 3< "$RUNTIME"', FINISH)
        self.assertNotRegex(INSTALL, r'(?<![0-9])< "\$RUNTIME"')
        self.assertIn("Input\\ArrayInput", PHP_SOURCE)
        self.assertIn("$registration = new Symfony\\Component\\Console\\Input\\ArrayInput([]);", PHP_SOURCE)
        self.assertIn("$registration->setInteractive(false);", PHP_SOURCE)
        self.assertIn("$application->loadCommands($registration, $output);", PHP_SOURCE)
        self.assertNotIn("$application->loadCommands($input, $output);", PHP_SOURCE)
        self.assertIn("'php://fd/3'", PHP_SOURCE)
        self.assertIn("CLOUD_APP . '/occ', $command", PHP_SOURCE)
        self.assertIn("'zend.exception_ignore_args', '1'", PHP_SOURCE)
        self.assertIn("ulimit -c 0", WORKER)
        self.assertNotIn("$error->getMessage()", PHP_SOURCE)
        self.assertNotIn("$error->getTrace", PHP_SOURCE)
        self.assertNotIn("case 'sql'", PHP_SOURCE)
        self.assertIn("$key === 'jwt_secret'", PHP_SOURCE)
        self.assertIn("setValueString($app", PHP_SOURCE)

    def test_private_diagnostics_are_retained_and_not_echoed(self):
        self.assertIn('install -d -o root -g wheel -m 700 "$STATE"', WORKER)
        self.assertIn('[ -e "$STATE/$diagnostic" ] || install -o root -g wheel -m 600', WORKER)
        for name in ["database-init.log", "nextcloud-install.log", "nextcloud-finish.log"]:
            self.assertIn(f"inspect $STATE/{name} (root-only)", WORKER)
            self.assertNotRegex(WORKER, rf"(?m)^\s*(?:cat|tail|tee)\b[^\n]*{re.escape(name)}")
        self.assertIn("new Symfony\\Component\\Console\\Output\\NullOutput()", PHP_SOURCE)
        self.assertIn("'logfile' => '/dev/null'", PHP_SOURCE)

    def test_preserves_production_ini_and_fpm_defaults_and_uses_db_dropin(self):
        for expected in ["pkg query '%Fp' \"$version_php_package\"", "php-config --ini-path", "php-config --ini-dir", "php.ini-production", 'json patch-ini "$TEMPLATES/$template" "$base"', "php-fpm.conf.default", "www.conf.default", "mysql/conf.d/zz-cloud-nextcloud.cnf"]:
            self.assertIn(expected, PREPARE)
        self.assertNotIn("!includedir", template("my.cnf"))
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string("[php]\n" + template("php.ini"))
        for name, value in {"expose_php": "Off", "display_errors": "Off", "display_startup_errors": "Off", "opcache.enable": "1", "opcache.jit": "disable", "apc.enable_cli": "1", "session.cookie_secure": "1", "session.cookie_httponly": "1", "zend.exception_ignore_args": "On"}.items():
            self.assertEqual(parser["php"][name], value)
        for text in ["pm = dynamic", "pm.max_requests = 500", "clear_env = yes", "rlimit_core = 0", "request_terminate_timeout = 3660s", "listen.mode = 0660"]:
            self.assertIn(text, template("www.conf"))
        self.assertIn("include = /usr/local/etc/php-fpm.d/www.conf", template("php-fpm.conf"))
        self.assertIn("cgi.fix_pathinfo = 1", template("php.ini"))
        self.assertIn("security.limit_extensions = .php", template("www.conf"))
        for mode in ("https.conf", "external.conf"):
            self.assertIn("ProxyFCGIBackendType FPM", template(mode))
            self.assertIn('<FilesMatch "\\.php$">', template(mode))
        self.assertIn("ProxyTimeout 3700", template("httpd.conf"))

    def test_database_durability_and_private_cache_sockets(self):
        for text in ["bind-address = 127.0.0.1", "innodb_flush_log_at_trx_commit = 1", "innodb_doublewrite = ON", "sync_binlog = 1", "binlog_expire_logs_seconds = 604800", "binlog_format = ROW", "transaction_isolation = READ-COMMITTED", "query_cache_type = 0", "collation_server = utf8mb4_bin"]:
            self.assertIn(text, template("my.cnf"))
        self.assertIn("mysql:unix_socket=/var/run/mysql/mysql.sock", PHP_SOURCE)
        self.assertIn("mariadb-install-db --basedir", WORKER)
        self.assertNotRegex(WORKER, r"(?m)^\s*mariadb-install-db")
        self.assertNotRegex(PHP_SOURCE + WORKER, r"(?:DELETE FROM|UPDATE) mysql\.(?:user|global_priv)")
        for text in ["port 0", "unixsocket /var/run/redis/private/nextcloud.sock", "unixsocketperm 660", "maxmemory-policy noeviction", 'save ""', "appendonly no"]:
            self.assertIn(text, template("redis.conf"))
        for text in ["# REQUIRE: LOGIN", "# BEFORE: php_fpm redis", "-o root -g www -m 750 /var/run/php-fpm", "-o redis -g redis -m 750 /var/run/redis/private"]:
            self.assertIn(text, template("cloud_php_dirs"))
        self.assertIn("pw groupmod redis -m www", WORKER)

    def test_uninstalled_application_is_never_published(self):
        challenge = template("challenge.conf") + template("httpd.conf")
        self.assertNotIn("/usr/local/www/nextcloud", challenge)
        self.assertNotIn("SetHandler", challenge)
        self.assertNotIn("Listen 443", challenge)
        self.assertNotIn("cloud-onlyoffice.conf", challenge)
        self.assertIn("php_fpm_enable=NO", PREPARE)
        self.assertNotIn("start_service php_fpm", PREPARE)
        self.assertLess(PUBLISH.index("installed_check"), PUBLISH.index("start_service php_fpm"))
        self.assertIn("require_phase installed", PUBLISH)
        for name in ["httpd.conf", "challenge.conf", "https.conf", "external.conf"]:
            stack = []
            for line in template(name).splitlines():
                tag = re.match(r"\s*<(/?)(\w+)(?:\s[^>]*)?>", line)
                if tag and tag[1]:
                    self.assertTrue(stack, name)
                    self.assertEqual(stack.pop(), tag[2], name)
                elif tag:
                    stack.append(tag[2])
            self.assertEqual(stack, [], name)

    def test_mimetype_repair_is_only_in_install_before_completion(self):
        self.assertEqual(WORKER.count('"$HELPER" mimetype-repair'), 1)
        self.assertNotIn('mimetype-repair', PUBLISH + FINISH)
        self.assertNotIn('--include-expensive', WORKER + PHP_SOURCE)
        ordered = ['"$HELPER" install', 'chmod 600 "$APP/config/config.php"',
                   '"$HELPER" mimetype-repair 3< "$RUNTIME" < /dev/null',
                   'touch "$STATE/nextcloud-installed"']
        self.assertEqual([INSTALL.index(step) for step in ordered], sorted(INSTALL.index(step) for step in ordered))

    def test_mimetype_phase_failure_retry_replay_and_publication_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'runtime.json').write_text(json.dumps(runtime()))
            (directory / 'nextcloud-database').touch()
            script = 'set -eu\n' + '\n'.join(
                f'{key}={shlex.quote(str(directory / value))}' for key, value in {
                    'STATE': '.', 'APP': 'app', 'RUNTIME': 'runtime.json', 'HELPER': 'helper.php',
                }.items()
            ) + '\nmode=install\n'
            script += 'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
            script += 'require_phase() { [ -f "$STATE/nextcloud-$1" ] || fail missing-phase; }\n'
            for stub in ['json', 'start_database_cache', 'chmod']:
                script += stub + '() { :; }\n'
            script += 'installed_check() { printf "checked\\n" >> "$STATE/calls"; }\n'
            script += r'''
mdo() {
    case "$*" in
        *mimetype-repair*)
            [ -f "$STATE/nextcloud-installed" ] && exit 90
            [ -z "$(cat)" ] || exit 91
            cmp -s /dev/fd/3 "$RUNTIME" || exit 92
            printf 'repair\n' >> "$STATE/calls"
            [ ! -f "$STATE/repair-fails" ] || return 1
            ;;
        *) cat > /dev/null; printf 'install\n' >> "$STATE/calls" ;;
    esac
}
'''
            script += INSTALL + '\ninstall_nextcloud\n'

            def run():
                return subprocess.run(['sh', '-c', script], input=json.dumps(secrets()), text=True, capture_output=True)

            failure = directory / 'repair-fails'
            failure.touch()
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Publication remains blocked', result.stderr)
            self.assertFalse((directory / 'nextcloud-installed').exists())
            # Exercise the real publication entry guard; all subsequent effects
            # are unreachable because the failed repair left no installed marker.
            blocked = subprocess.run(['sh', '-c', script.split(INSTALL)[0] + PUBLISH + '\npublish'],
                                     text=True, capture_output=True)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn('missing-phase', blocked.stderr)
            self.assertFalse((directory / 'nextcloud-published').exists())
            failure.unlink()
            self.assertEqual(run().returncode, 0)
            self.assertTrue((directory / 'nextcloud-installed').is_file())
            calls = (directory / 'calls').read_text().splitlines()
            self.assertEqual(calls, ['install', 'checked', 'repair'] * 2)
            (directory / 'nextcloud-published').touch()
            self.assertEqual(run().returncode, 0)
            self.assertEqual((directory / 'calls').read_text().splitlines(), calls + ['install', 'checked'])
            (directory / 'nextcloud-installed').unlink()
            for marker in ['published', 'finished']:
                with self.subTest(marker=marker):
                    (directory / 'nextcloud-published').unlink(missing_ok=True)
                    (directory / f'nextcloud-{marker}').touch()
                    result = run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('refusing fresh-install repair', result.stderr)
                    self.assertEqual((directory / 'calls').read_text().splitlines(), calls + ['install', 'checked'])
                    self.assertFalse((directory / 'nextcloud-installed').exists())

    def test_tls_is_webroot_or_host_provided_and_verification_stays_enabled(self):
        for name in ["privkey", "fullchain"]:
            self.assertIn(f'install -m 600 "$PAYLOAD/tls/{name}.pem" /usr/local/etc/cloud-tls/{name}.pem', PUBLISH)
        self.assertIn("certbot certonly --webroot", PUBLISH)
        self.assertIn("--keep-until-expiring", PUBLISH)
        self.assertNotRegex(WORKER, r"openssl\s+req|--standalone|--no-verify-ssl")
        hook = template("certbot-deploy")
        self.assertLess(hook.index("configtest"), hook.index("apache24 graceful"))
        self.assertNotRegex(hook, r"apache24 (?:stop|restart)")
        self.assertIn("--deploy-hook /usr/local/libexec/cloud-certbot-deploy", template("certbot-cron"))
        self.assertIn("Alias /.well-known/acme-challenge/", template("https.conf"))
        self.assertIn("SSLProtocol -all +TLSv1.2 +TLSv1.3", template("https.conf"))
        formats = re.findall(r"^LogFormat (.+)$", template("httpd.conf"), re.MULTILINE)
        self.assertTrue(formats)
        self.assertFalse(any(token in line for line in formats for token in ["%r", "%q", "Referer", "Authorization"]))

    def test_finish_repeats_pinned_connector_import_cron_and_permission_pass(self):
        for text in ['"$HELPER" connector-install 3< "$RUNTIME" 4< "$PAYLOAD/connector.json" < /dev/null', '"$HELPER" connector-import', "occ onlyoffice:documentserver --check", "occ background:cron", "crontab -u www"]:
            self.assertIn(text, FINISH)
        self.assertIn('private_file "$PAYLOAD/connector.json" 65536', FINISH)
        self.assertEqual(WORKER.count('4< "$PAYLOAD/connector.json"'), 1)
        self.assertNotRegex(FINISH, r"occ app:(?:install|enable)|--force")
        self.assertLess(FINISH.index('"$HELPER" connector-install'), FINISH.index('"$HELPER" connector-import'))
        self.assertLess(FINISH.index('"$HELPER" connector-import'), FINISH.index('install -m 600 "$PAYLOAD/apache-onlyoffice.conf"'))
        self.assertLess(FINISH.index("apachectl configtest"), FINISH.index("service apache24 graceful"))
        pruned = '\\( -path "$APP/config" -o -path "$APP/custom_apps" \\) -prune -o'
        self.assertEqual(FINISH.count(pruned), 2)
        self.assertIn("-exec chown -h root:www {} +", FINISH)
        self.assertIn("-exec chmod u=rwX,g=rX,o= {} +", FINISH)
        self.assertIn('chmod 600 "$APP/config/config.php"', FINISH)
        self.assertLess(FINISH.index('php -f "$APP/cron.php"'), FINISH.index("-exec chown -h root:www"))
        self.assertIn("*/5 * * * * /usr/local/bin/php", template("www-crontab"))

    def test_logrotation_has_finite_retention_and_safe_reopen(self):
        rows = {}
        for line in template("newsyslog.conf").splitlines():
            if not line or line.startswith("#"):
                continue
            row = line.split()
            rows[row[0]] = row
            self.assertIn(row[2], ["600", "640"])
            self.assertEqual(int(row[3]), 7)
            self.assertGreater(int(row[4]), 0)
            self.assertLessEqual(int(row[4]), 65536)
            self.assertEqual(row[5], "24")
            self.assertTrue(set("BEPZ") <= set(row[6]))
        for path in ["/var/log/httpd-access.log", "/var/log/httpd-error.log"]:
            self.assertEqual(rows[path][7:], ["/var/run/httpd.pid", "SIGUSR1"])
        self.assertEqual(rows["/var/log/php-fpm/fpm.log"][7:], ["/var/run/php-fpm.pid", "SIGUSR1"])
        for path in ["/var/log/mysql/mysqld.err", "/var/log/mysql/slow.log"]:
            self.assertEqual(rows[path][7:], ["/usr/local/libexec/cloud-mysql-flush-logs"])
            self.assertIn("R", rows[path][6])
        self.assertEqual(rows["/var/log/nextcloud/cron.log"][1], "www:www")
        hook = template("mysql-flush-logs")
        self.assertIn("--no-defaults --protocol=socket", hook)
        self.assertIn("FLUSH NO_WRITE_TO_BINLOG ERROR LOGS; FLUSH NO_WRITE_TO_BINLOG SLOW LOGS;", hook)
        self.assertNotRegex(hook, r"(?m)^\s*(?:kill|pkill)|service mysql-server (?:stop|restart)|--password")

    def test_isolated_secret_phases_preserve_stdin_and_keep_argv_public(self):
        # Run only extracted function bodies with command stubs, NEVER the worker.
        # mdo's stand-in checks the inherited public fd and secret input itself.
        for name, document, command in [
            ("install_nextcloud", secrets(), "install"),
            ("finish", connector(runtime()), "connector-import"),
            ("checkpoint_ready", {"db_password": secrets()["db_password"]}, "checkpoint-ready"),
        ]:
            with self.subTest(phase=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                (directory / "runtime.json").write_text(json.dumps(runtime()))
                (directory / "runtime.json").chmod(0o600)
                (directory / "connector.json").write_text(connector_record_text())
                (directory / "connector.json").chmod(0o600)
                probe = (
                    "import json,os,sys; "
                    "args=sys.argv[1:]; "
                    "is_secret=any(x in args for x in ['install','connector-import','checkpoint-ready']); "
                    "is_connector='connector-install' in args; "
                    "is_mimetype='mimetype-repair' in args; "
                    "raw=sys.stdin.read(); "
                    "assert bool(raw)==is_secret; "
                    "p=json.loads(raw) if raw else {}; "
                    "assert not any(v in ' '.join(args) for v in " + repr(list(secrets().values()) + [connector(runtime())["apps"]["onlyoffice"]["jwt_secret"]]) + "); "
                    "c=json.load(os.fdopen(3)) if is_secret or is_connector or is_mimetype else {}; "
                    "assert not c or ('db_password' not in c and c['public_hostname']=='cloud.example.com'); "
                    "locked=json.load(os.fdopen(4)) if is_connector else {}; "
                    "assert not locked or locked==" + repr(connector_record()) + "; "
                    "assert not p or set(p)==({'apps'} if 'connector-import' in args else {'db_password'} if 'checkpoint-ready' in args else {'admin_password','db_password'}); "
                    "exec(\"if not is_connector:\\n try: os.fstat(4)\\n except OSError: pass\\n else: raise AssertionError('unexpected public connector fd')\"); "
                    "print('stdin checked' if is_secret else 'connector fd checked' if is_connector else 'cron stub')"
                )
                script = "set -eu\n" + "\n".join(
                    f"{key}={shlex.quote(str(directory / value))}" for key, value in {
                        "STATE": ".", "APP": "app", "PAYLOAD": ".", "RUNTIME": "runtime.json", "HELPER": "helper.php", "TEMPLATES": ".",
                    }.items()
                ) + "\n"
                script += "version_office_backend=onlyoffice\n"
                script += "fail() { exit 1; }\n"
                for stub in ["require_phase", "json", "installed_check", "private_file", "install", "apachectl", "service", "crontab", "start_service", "start_database_cache", "find", "chmod", "touch", "close_cron", "cron_closed", "sysrc", "install_optional_apps"]:
                    script += stub + "() { :; }\n"
                script += "cron_check() { printf '%s\\n' present; }\n"
                script += "occ() { cat >/dev/null; }\n"  # Detect accidental stdin consumption.
                script += "mdo() { " + shlex.quote(shutil.which("python3")) + " -c " + shlex.quote(probe) + ' "$@"; }\n'
                # Cron redirection is also kept inside the approved fixture tree.
                script += phase(name).replace("/var/log/nextcloud/cron.log", str(directory / "cron.log")) + "\n" + name
                result = subprocess.run(["sh", "-c", script], input=json.dumps(document), text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                log = directory / {"install": "nextcloud-install.log", "connector-import": "nextcloud-finish.log", "checkpoint-ready": "database-init.log"}[command]
                self.assertIn("stdin checked", log.read_text())
                if name == "finish":
                    self.assertIn("connector fd checked", log.read_text())
                for value in list(secrets().values()) + [connector(runtime())["apps"]["onlyoffice"]["jwt_secret"]]:
                    self.assertNotIn(value, result.stdout + result.stderr + log.read_text())


# Native API stand-ins: exercise the real wrapper/fetcher and its ordering, not
# Nextcloud's cryptography. All file effects stay in the supplied temporary tree.
CONNECTOR_NATIVE_STUBS = r'''
namespace OC\App\AppStore\Fetcher {
    class AppFetcher {
        public function __construct() { throw new \RuntimeException('Mutable fetcher constructed'); }
        public function get($allowUnstable = false): array {
            $GLOBALS['calls'][] = 'mutable-latest';
            return [['id' => 'onlyoffice', 'releases' => [['version' => '10.2.2']]]];
        }
    }
}
namespace OCP {
    class Server {
        public static function get(string $name): object {
            $GLOBALS['services_requested'][] = $name;
            return $GLOBALS['services'][$name];
        }
    }
}
namespace OC {
    class Installer {
        public function __construct(public \OC\App\AppStore\Fetcher\AppFetcher $fetcher,
            object $client, object $temp, object $logger, object $config,
            private object $manager, object $l10n, bool $isCLI) {
            if (!$isCLI) throw new \RuntimeException('CLI installer required');
        }
        public function getInstallPath(): ?string { return $GLOBALS['p']['install_root'] ?? dirname($GLOBALS['p']['path']); }
        public function downloadApp(string $id, bool $unstable = false): void {
            if ($id !== 'onlyoffice' || $unstable) throw new \RuntimeException('Unexpected download');
            $GLOBALS['calls'][] = 'download';
            $GLOBALS['downloaded'] = $this->fetcher->get($unstable);
            if ($GLOBALS['p']['download_error'] ?? false) throw new \RuntimeException('Native archive authentication failed');
            foreach ($GLOBALS['p']['files'] as $name => $bytes) {
                $file = $GLOBALS['p']['path'] . '/' . $name;
                if (!is_dir(dirname($file))) mkdir(dirname($file), 0700, true);
                file_put_contents($file, $bytes);
            }
        }
        public function installApp(string $id, bool $force = false): string {
            if ($id !== 'onlyoffice' || $force) throw new \RuntimeException('Unexpected migration');
            $GLOBALS['calls'][] = 'install';
            if ($GLOBALS['p']['install_error'] ?? false) throw new \RuntimeException('Interrupted native install');
            $this->manager->installed = $GLOBALS['p']['installed_result'] ?? $GLOBALS['c']['versions']['connector'];
            return $id;
        }
    }
}
namespace {
    class ConnectorManager {
        public function __construct(public string $installed) {}
        public function getAppInstalledVersions(): array { throw new RuntimeException('Process-cached app inventory cannot verify installation writes'); }
        public function getAppPath(string $id, bool $ignoreCache): string {
            if ($id !== 'onlyoffice' || !$ignoreCache) throw new RuntimeException('Unexpected path lookup');
            return $GLOBALS['p']['app_path'] ?? $GLOBALS['p']['path'];
        }
        public function clearAppsCache(): void { $GLOBALS['calls'][] = 'clear-cache'; }
        public function getAppInfo(string $id): array {
            $GLOBALS['calls'][] = 'info';
            $xml = file_get_contents($GLOBALS['p']['path'] . '/appinfo/info.xml');
            preg_match('~<version>([^<]+)</version>~', $xml, $match);
            preg_match('~<id>([^<]+)</id>~', $xml, $app);
            return ['id' => $app[1], 'version' => $match[1]];
        }
        public function isAppCompatible(string $version, array $info, bool $ignoreMax): bool {
            if ($ignoreMax || $version !== $GLOBALS['c']['versions']['nextcloud']) throw new RuntimeException('Forced compatibility');
            $GLOBALS['calls'][] = 'compatible';
            return $GLOBALS['p']['compatible'] ?? true;
        }
        public function checkAppDependencies(string $id, bool $ignoreMax): void {
            if ($id !== 'onlyoffice' || $ignoreMax) throw new RuntimeException('Forced dependencies');
            $GLOBALS['calls'][] = 'dependencies';
            if ($GLOBALS['p']['dependency_error'] ?? false) throw new RuntimeException('Missing dependency');
        }
        public function isEnabledForAnyone(string $id): bool { return $GLOBALS['p']['enabled'] ?? false; }
        public function enableApp(string $id, bool $force): void {
            if ($id !== 'onlyoffice' || $force) throw new RuntimeException('Forced enable');
            $GLOBALS['calls'][] = 'enable';
        }
    }
    class ConnectorConfig {
        public function getAppValue(string $app, string $key, string $default): string {
            if ($app !== 'onlyoffice' || $key !== 'installed_version') throw new RuntimeException('Unexpected app config key');
            return $GLOBALS['manager']->installed;
        }
        public function getSystemValue(string $key, mixed $default): mixed {
            if ($key !== 'cloud_installer_connector_auth') throw new RuntimeException('Unexpected config key');
            return is_file($GLOBALS['p']['receipt_path']) ? json_decode(file_get_contents($GLOBALS['p']['receipt_path']), true, 32, JSON_THROW_ON_ERROR) : $default;
        }
        public function setSystemValue(string $key, mixed $value): void {
            $GLOBALS['calls'][] = 'receipt';
            if ($GLOBALS['p']['receipt_error'] ?? false) throw new RuntimeException('Config write failed');
            if (!($GLOBALS['p']['receipt_discard'] ?? false)) file_put_contents($GLOBALS['p']['receipt_path'], json_encode($value, JSON_THROW_ON_ERROR));
        }
    }
    class ConnectorChecker {
        public function verifyAppSignature(string $id, string $path, bool $forceVerify): array {
            if ($id !== 'onlyoffice' || !$forceVerify) throw new RuntimeException('Native verification was not forced');
            $GLOBALS['calls'][] = 'verify';
            $manifest = json_decode(file_get_contents($path . '/appinfo/signature.json'), true, 32, JSON_THROW_ON_ERROR);
            if ($manifest['signature'] !== 'offline native-checker fixture') return ['EXCEPTION' => ['message' => 'Invalid signature']];
            $expected = $manifest['hashes'];
            $actual = [];
            foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)) as $file) {
                $name = substr($file->getPathname(), strlen($path) + 1);
                if ($name !== 'appinfo/signature.json') $actual[$name] = hash_file('sha512', $file->getPathname());
            }
            if (array_diff_key($expected, $actual)) return ['FILE_MISSING' => []];
            if (array_diff_key($actual, $expected)) return ['EXTRA_FILE' => []];
            if (array_diff_assoc($expected, $actual)) return ['INVALID_HASH' => []];
            return [];
        }
    }
}
'''


@unittest.skipUnless(PHP, "PHP >= 8.1 CLI is unavailable")
class NextcloudPHPTests(unittest.TestCase):
    php = staticmethod(run_php)

    def connector_apply(self, directory, **overrides):
        payload = {"runtime": runtime(), "record_text": connector_record_text(),
                   "path": str(directory / "onlyoffice"), "receipt_path": str(directory / "receipt.json"),
                   "files": connector_tree(), **overrides}
        expression = r'''
$calls = $services_requested = $downloaded = [];
$manager = new ConnectorManager($p['installed'] ?? '');
$config = new ConnectorConfig();
$services = [
    OCP\Http\Client\IClientService::class => new stdClass(), OCP\ITempManager::class => new stdClass(),
    Psr\Log\LoggerInterface::class => new stdClass(), OCP\IConfig::class => $config,
    OC\App\AppManager::class => $manager, OCP\L10N\IFactory::class => new stdClass(),
];
try {
    $record = cloudConnectorRecord($c, $p['record_text']);
    $installer = cloudConnectorInstaller($record, cloudConnectorId($c));
    try { $installer->fetcher->get(true); throw new RuntimeException('Unstable metadata accepted'); }
    catch (CloudFailure $expected) {}
    cloudConnectorApply($c, $record, $p['path'], $installer, $manager, $config, new ConnectorChecker());
    $ok = true; $diagnostic = '';
} catch (Throwable $e) { $ok = false; $diagnostic = cloudDiagnostic($e); }
echo json_encode(['ok' => $ok, 'calls' => $calls, 'downloaded' => $downloaded,
    'services' => $services_requested, 'diagnostic' => $diagnostic], JSON_THROW_ON_ERROR);
'''
        result = self.php(expression, payload, prelude=CONNECTOR_NATIVE_STUBS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_php_syntax(self):
        result = subprocess.run([PHP, "-l", str(HELPER)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mimetype_native_step_postcondition_and_protected_dispatch(self):
        # Exercise the actual dispatcher and repair wrapper. Replace only the
        # installed-instance/boot boundaries, which require a real jail and DB.
        # Native repair and container stand-ins record every requested operation.
        prelude = r'''
namespace OCP {
    class Util {
        public static function needUpgrade(): bool {
            $GLOBALS['calls'][] = 'upgrade-check';
            return $GLOBALS['scenario'] === 'upgrade';
        }
    }
    class Server {
        public static function get(string $name): object {
            $GLOBALS['calls'][] = $name;
            if ($name !== \OC\Repair\RepairMimeTypes::class) throw new \RuntimeException('Unrelated repair service');
            return new \OC\Repair\RepairMimeTypes();
        }
    }
}
namespace OC\Migration { class NullOutput {} }
namespace OC\Repair {
    class RepairMimeTypes {
        public function run(\OC\Migration\NullOutput $output): void {
            $GLOBALS['calls'][] = 'run';
            echo str_repeat('secret-upstream-output', 1000);
            trigger_error('secret-upstream-warning', E_USER_WARNING);
            if ($GLOBALS['scenario'] === 'error') throw new \RuntimeException('secret-upstream-exception');
        }
        public function migrationsAvailable(): bool {
            $GLOBALS['calls'][] = 'postcondition';
            if ($GLOBALS['scenario'] === 'check-error') throw new \RuntimeException('secret-check-exception');
            return $GLOBALS['scenario'] === 'pending';
        }
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            c = runtime()
            c['versions']['php'] = subprocess.check_output([PHP, '-r', 'echo PHP_VERSION;'], text=True)
            public = directory / 'runtime.json'
            calls = directory / 'calls.json'
            public.write_text(json.dumps(c))
            isolated = PHP_SOURCE.removeprefix('<?php').replace(
                "const CLOUD_RUNTIME = '/root/cloud-installer/runtime.json';",
                'const CLOUD_RUNTIME = ' + json.dumps(str(public)) + ';')
            for name, replacement in {
                'cloudInstalled': '''function cloudInstalled(array $c): void {
                    $GLOBALS['calls'][] = 'installed-check';
                    if ($GLOBALS['scenario'] === 'identity') cloudFail(21);
                }''',
                'cloudBoot': '''function cloudBoot(array $c, string $command): void {
                    $GLOBALS['calls'][] = 'boot:' . $command;
                    echo 'secret-boot-output';
                }''',
            }.items():
                isolated, count = re.subn(r'(?ms)^function ' + name + r'\(.*?^\}', lambda _: replacement, isolated)
                self.assertEqual(count, 1)
            fixture = directory / 'helper.php'
            fixture.write_text('<?php' + isolated)
            for scenario in ['success', 'pending', 'error', 'check-error', 'upgrade', 'identity']:
                with self.subTest(scenario=scenario):
                    code = prelude + 'namespace { define("CLOUD_NEXTCLOUD_LIBRARY", true); require ' + json.dumps(str(fixture)) + ';'
                    code += '$calls=[]; $scenario=' + json.dumps(scenario) + ';'
                    code += '$status=cloudMain(["helper", "mimetype-repair"]);'
                    code += 'if (stream_get_contents(STDIN) !== "untouched-secret-input") exit(99);'
                    code += 'file_put_contents(' + json.dumps(str(calls)) + ', json_encode($calls)); exit($status); }'
                    result = subprocess.run(['sh', '-c', 'exec ' + shlex.quote(PHP) + ' -r ' + shlex.quote(code)
                                             + ' 3< ' + shlex.quote(str(public))],
                                            input='untouched-secret-input', text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0 if scenario == 'success' else 1, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertNotIn('secret-', result.stderr)
                    expected = ['installed-check']
                    if scenario != 'identity':
                        expected += ['boot:mimetype-repair', 'upgrade-check']
                    if scenario not in ['identity', 'upgrade']:
                        expected += ['OC\\Repair\\RepairMimeTypes', 'run']
                        if scenario != 'error':
                            expected += ['postcondition']
                    self.assertEqual(json.loads(calls.read_text()), expected)
                    if scenario == 'pending':
                        self.assertIn('migrations remain pending', result.stderr)
                    elif scenario in ['error', 'check-error']:
                        self.assertIn('Raw exception output was suppressed', result.stderr)

    def test_versions_are_required_exact_public_scalars(self):
        good = runtime()["versions"]
        invalid = [None, [], {}, dict(good, extra="secret")]
        for key in good:
            invalid.append({name: value for name, value in good.items() if name != key})
            for value in [None, 123, True, [], good[key] + "\n", '"; touch /tmp/not-run', "$(id)"]:
                invalid.append(dict(good, **{key: value}))
        for versions in invalid:
            with self.subTest(versions=versions):
                result = self.php("echo 'accepted';", {"runtime": dict(runtime(), versions=versions)})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        missing = runtime()
        del missing["versions"]
        self.assertNotEqual(self.php("echo 'accepted';", {"runtime": missing}).returncode, 0)

    def test_selected_php_and_database_versions_are_exact_without_prefix_guesses(self):
        c = runtime()
        c["versions"].update(php="8.6.12", php_package="php86", database="12.4.2")
        for actual, size, accepted in [("8.6.12", 8, True), ("8.6.12", 4, False),
                                       ("8.6.1", 8, False), ("8.6.13", 8, False), ("8.6.12-dev", 8, False)]:
            result = self.php("cloudPHPEnvironment($c,$p['actual'],$p['size']); echo 'ok';",
                              {"runtime": c, "actual": actual, "size": size})
            self.assertEqual(result.returncode == 0, accepted, result.stderr)
        for actual, accepted in [("12.4.2-MariaDB", True), ("12.4.2-MariaDB-log", True),
                                 ("12.4.1-MariaDB", False), ("12.4.20-MariaDB", False),
                                 ("12.4.2-MySQL", False), ("12.4.2", False)]:
            result = self.php("cloudDatabaseVersion($c,$p['actual']); echo 'ok';", {"runtime": c, "actual": actual})
            self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_connector_pin_precedes_native_migrations_and_enable(self):
        install = PHP_SOURCE.split("function cloudConnectorApply(", 1)[1].split("\nfunction ", 1)[0]
        ordered = ["downloadApp($app, false)", "cloudConnectorTree($record, $path, $checker, $app)",
                   "cloudConnectorVersion($c, $info)", "isAppCompatible(", "checkAppDependencies($app, false)",
                   "setSystemValue($key, $receipt)", "installApp($app, false)",
                   "enableApp($app, false)"]
        self.assertEqual([install.index(value) for value in ordered], sorted(install.index(value) for value in ordered))
        self.assertNotIn("->getAppInstalledVersions(", install)
        self.assertEqual(install.count("$config->getAppValue($app, 'installed_version', '')"), 2)
        entry = PHP_SOURCE.split("function cloudConnectorInstall(", 1)[1].split("\nfunction ", 1)[0]
        self.assertLess(entry.index("cloudConnectorRead($c)"), entry.index("cloudInstalled($c)"))
        self.assertLess(entry.index("cloudConnectorRead($c)"), entry.index("cloudBoot($c"))
        for version, accepted in [("10.2.1", True), ("10.2.2", False), ("10.2.10", False), ("10.1.9", False)]:
            result = self.php("cloudConnectorVersion($c,$p['info']); echo 'ok';",
                              {"runtime": runtime(), "info": {"id": "onlyoffice", "version": version}})
            self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_connector_phases_use_nc35_public_upgrade_guard(self):
        # NC35 Console/Application.php imports OCP\Util, not the removed OC\Util.
        for name, operation in [("cloudConnectorInstall", "cloudConnectorApply("),
                                ("cloudConnectorImport", "$manager =")]:
            entry = PHP_SOURCE.split("function " + name + "(", 1)[1].split("\nfunction ", 1)[0]
            self.assertNotIn("OC\\Util::needUpgrade()", entry)
            self.assertLess(entry.index("cloudBoot($c"), entry.index("OCP\\Util::needUpgrade()"))
            self.assertLess(entry.index("OCP\\Util::needUpgrade()"), entry.index(operation))
            guard = entry[entry.index("if (OCP\\Util::needUpgrade())"):].split("\n    }", 1)[0] + "\n    }"
            prelude = "namespace OCP { class Util { public static function needUpgrade() { return $GLOBALS['p']['upgrade']; } } }"
            for upgrade in (False, True):
                result = self.php(guard + " echo 'ready';", {"runtime": runtime(), "upgrade": upgrade}, prelude=prelude)
                self.assertEqual(result.returncode == 0, not upgrade)
                self.assertEqual(result.stdout, "" if upgrade else "ready")

    def test_connector_finish_restarts_fpm_before_live_callback_check(self):
        finish = WORKER.split("finish() {", 1)[1].split("\n}", 1)[0]
        ordered = ['"$HELPER" connector-install', '"$HELPER" connector-import',
                   'service php_fpm restart < /dev/null', 'service apache24 graceful < /dev/null',
                   'occ onlyoffice:documentserver --check < /dev/null', 'touch "$STATE/nextcloud-finished"']
        self.assertEqual([finish.index(step) for step in ordered], sorted(finish.index(step) for step in ordered))
        self.assertNotIn("|| true", finish)

    def test_connector_record_requires_exact_bytes_and_shaped_signed_metadata(self):
        expression = "echo json_encode(cloudConnectorRecord($c,$p['text']),JSON_THROW_ON_ERROR);"
        good = connector_record()
        result = self.php(expression, {"runtime": runtime(), "text": connector_record_text()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), good)
        invalid = [{key: value for key, value in good.items() if key != missing} for missing in good]
        invalid += [dict(good, **{key: value}) for key, value in [
            ("extra", "unexpected"), ("version", "10.2.2"), ("version", "10.2.1-beta1"),
            ("isNightly", True), ("isNightly", 0), ("signatureDigest", "sha256"),
            ("phpVersionSpec", ">=8.2"), ("platformVersionSpec", "*"),
            ("download", "http://example.test/archive.tar.gz"),
            ("download", "https://user:password@example.test/archive.tar.gz"),
            ("download", "https://example.test/archive.tar.gz#fragment"),
            ("download", "https://example.test/archive\\file.tar.gz"),
            ("download", "https://example.test/archive\n.tar.gz"),
            ("signature", ""), ("signature", "not base64!"), ("signature", "YQ="),
            ("signature", None), ("certificate", "unsigned"), ("certificate", False),
            ("certificate", "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"),
            ("certificate", "x" * 65536),
        ]]
        for record in invalid:
            with self.subTest(record=record if len(str(record)) < 2048 else "oversized"):
                text = connector_record_text(record)
                c = runtime()
                c["versions"]["connector_sha256"] = hashlib.sha256(text.encode()).hexdigest()
                result = self.php(expression, {"runtime": c, "text": text})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        for text in [connector_record_text().rstrip("\n"), connector_record_text() + "\n", connector_record_text(dict(good, version="10.2.2"))]:
            self.assertNotEqual(self.php(expression, {"runtime": runtime(), "text": text}).returncode, 0)

    def test_connector_authoritative_folded_base64_is_preserved_not_rewritten(self):
        for newline in ("\n", "\r\n"):
            record = connector_record()
            value = record["signature"]
            record["signature"] = newline.join(value[i:i + 8] for i in range(0, len(value), 8)) + newline
            text = connector_record_text(record)
            config = runtime()
            config["versions"]["connector_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            result = self.php("echo json_encode(cloudConnectorRecord($c,$p['text']),JSON_THROW_ON_ERROR);",
                              {"runtime": config, "text": text})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), record)

    def test_connector_native_installer_gets_only_the_retained_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            result = self.connector_apply(directory)
            self.assertTrue(result["ok"], result)
            record = connector_record()
            self.assertEqual(result["downloaded"], [{"id": "onlyoffice", "certificate": record["certificate"], "releases": [record]}])
            self.assertNotIn("mutable-latest", result["calls"])
            self.assertEqual(result["services"], ["OCP\\Http\\Client\\IClientService", "OCP\\ITempManager", "Psr\\Log\\LoggerInterface", "OCP\\IConfig", "OC\\App\\AppManager", "OCP\\L10N\\IFactory"])
            ordered = ["download", "verify", "info", "compatible", "dependencies", "receipt", "install", "enable"]
            self.assertEqual([result["calls"].index(call) for call in ordered], sorted(result["calls"].index(call) for call in ordered))
            self.assertEqual(json.loads((directory / "receipt.json").read_text()), {
                "record_sha256": runtime()["versions"]["connector_sha256"],
                "manifest_sha256": hashlib.sha256((directory / "onlyoffice/appinfo/signature.json").read_bytes()).hexdigest(),
            })

    def test_connector_untrusted_record_never_reaches_native_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            result = self.connector_apply(directory, record_text=connector_record_text().rstrip("\n"))
            self.assertFalse(result["ok"])
            self.assertEqual(result["services"], [])
            self.assertEqual(result["calls"], [])
            self.assertEqual(list(directory.iterdir()), [])

    def test_connector_partial_download_cannot_be_retried_or_adopted(self):
        for missing in ["lib/Application.php", "appinfo/signature.json"]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                files = connector_tree()
                del files[missing]
                first = self.connector_apply(directory, files=files)
                self.assertFalse(first["ok"], first)
                self.assertIn("download", first["calls"])
                self.assertNotIn("install", first["calls"])
                self.assertNotIn("enable", first["calls"])
                self.assertFalse((directory / "receipt.json").exists())
                # info.xml still matches exactly, but an incomplete copy is not adopted.
                retry = self.connector_apply(directory)
                self.assertFalse(retry["ok"], retry)
                self.assertEqual(retry["calls"], [])
                self.assertIn("explicit recovery", retry["diagnostic"])
                self.assertIn("Automatic overwrite or adoption is refused", retry["diagnostic"])
                actual = {str(p.relative_to(directory / "onlyoffice")): p.read_text() for p in (directory / "onlyoffice").rglob("*") if p.is_file()}
                self.assertEqual(actual, files)

    def test_connector_complete_unknown_tree_also_requires_authentication_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, text in connector_tree().items():
                path = directory / "onlyoffice" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            for installed in ["", "10.2.1"]:
                result = self.connector_apply(directory, installed=installed)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["calls"], [])
                self.assertFalse((directory / "receipt.json").exists())

    def test_connector_receipt_survives_interrupted_install_and_resume_reverifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            first = self.connector_apply(directory, install_error=True)
            self.assertFalse(first["ok"])
            self.assertIn("install", first["calls"])
            self.assertNotIn("enable", first["calls"])
            self.assertTrue((directory / "receipt.json").is_file())
            # Separate PHP processes: receipt is read from persistent config, not memory.
            retry = self.connector_apply(directory)
            self.assertTrue(retry["ok"], retry)
            self.assertNotIn("download", retry["calls"])
            self.assertLess(retry["calls"].index("verify"), retry["calls"].index("install"))
            again = self.connector_apply(directory, installed="10.2.1", enabled=True)
            self.assertTrue(again["ok"], again)
            self.assertIn("verify", again["calls"])
            for call in ["download", "install", "enable"]:
                self.assertNotIn(call, again["calls"])

    def test_connector_changed_receipted_tree_cannot_install_or_enable(self):
        for change in ["missing", "extra", "modified", "unsigned", "manifest-missing", "manifest-changed", "certificate", "symlink", "record-receipt"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                self.assertTrue(self.connector_apply(directory)["ok"])
                app = directory / "onlyoffice"
                code = app / "lib/Application.php"
                manifest = app / "appinfo/signature.json"
                if change == "missing":
                    code.unlink()
                elif change == "extra":
                    (app / "unsigned.php").write_text("unsigned executable")
                elif change == "modified":
                    code.write_text("different executable")
                elif change == "manifest-missing":
                    manifest.unlink()
                elif change == "manifest-changed":
                    manifest.write_text(manifest.read_text() + "\n")
                elif change in ("unsigned", "certificate"):
                    data = json.loads(manifest.read_text())
                    data["signature" if change == "unsigned" else "certificate"] = "invalid" if change == "unsigned" else connector_record()["certificate"].replace("b2ZmbGluZSBjZXJ0aWZpY2F0ZQ==", "ZGlmZmVyZW50")
                    manifest.write_text(json.dumps(data))
                elif change == "symlink":
                    code.unlink()
                    code.symlink_to(app / "appinfo/info.xml")
                else:
                    receipt = directory / "receipt.json"
                    data = json.loads(receipt.read_text())
                    data["record_sha256"] = "0" * 64
                    receipt.write_text(json.dumps(data))
                # Check both pre-migration and already-installed enable paths.
                for installed in ["", "10.2.1"]:
                    result = self.connector_apply(directory, installed=installed)
                    self.assertFalse(result["ok"], result)
                    for call in ["download", "install", "enable"]:
                        self.assertNotIn(call, result["calls"])

    def test_connector_native_or_receipt_failures_stop_before_migration(self):
        for options in [{"download_error": True}, {"compatible": False}, {"dependency_error": True},
                        {"receipt_error": True}, {"receipt_discard": True},
                        {"install_root": "/wrong-destination"}, {"app_path": "/unexpected-app"}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                result = self.connector_apply(directory, **options)
                self.assertFalse(result["ok"], result)
                self.assertNotIn("install", result["calls"])
                self.assertNotIn("enable", result["calls"])
                self.assertFalse((directory / "receipt.json").exists())

    def test_connector_code_and_database_version_drift_never_enable(self):
        for options in [{"files": connector_tree("10.2.2")}, {"installed": "10.2.2"}, {"installed_result": "10.2.2"}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                result = self.connector_apply(Path(tmp), **options)
                self.assertFalse(result["ok"], result)
                if "installed_result" not in options:
                    self.assertNotIn("install", result["calls"])
                self.assertNotIn("enable", result["calls"])

    def test_public_config_rejects_all_secrets_unknown_keys_and_injection(self):
        invalid = {
            "admin_password": [secrets()["admin_password"], None], "db_password": [secrets()["db_password"]],
            "jwt_secret": ["x" * 64], "credentials": [secrets()], "onlyoffice_sql": [True],
            "public_hostname": ["cloud.example.com\nInclude /tmp/x", "cloud.example.com:443", "127.0.0.1", "*.example.com"],
            "public_url": ["http://cloud.example.com/", "https://evil.example/", "https://cloud.example.com/path/", "https://cloud.example.com:0/", "https://cloud.example.com:65536/", "https://cloud.example.com:0443/", "https://cloud.example.com/?x=1"],
            "storage_url": ["https://cloud.example.com:8443/", "http://10.77.0.2/"],
            "timezone": ['UTC"\nexpose_php=On', "../UTC"],
            "admin_email": ["a@example.com\nServerName evil"],
            "nextcloud_ip": ["127.0.0.1", "8.8.8.8", "::1", "10.77.0.6"],
            "db_name": ["other", "nextcloud`; DROP DATABASE mysql;"],
            "repository": ["latest;touch /tmp/x", "FreeBSD-base"],
            "tls_mode": ["off", "selfsigned"], "proxy_networks": [["192.0.2.1/32"]],
            "php_children": [0, 1, 513, "8", True], "php_memory_mb": [511, -1, "512"], "redis_memory_mb": [0],
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    result = self.php("echo 'accepted';", {"runtime": dict(runtime(), **{key: value})})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    for secret in secrets().values():
                        self.assertNotIn(secret, result.stderr)

    def test_proxy_cidrs_are_canonical_ipv4_and_never_trust_everyone(self):
        for networks in [[], ["0.0.0.0/0"], ["::/0"], ["192.0.2.7/24"], ["192.0.2.1"], ["198.51.100.7/32\nRequire all granted"], ["192.0.2.0/24", "192.0.2.0/24"], {"network": "192.0.2.0/24"}]:
            result = self.php("echo 'accepted';", {"runtime": dict(runtime("external"), proxy_networks=networks)})
            self.assertNotEqual(result.returncode, 0)
        for port in [None, 443, 8443, 65535]:
            result = self.php("echo 'accepted';", {"runtime": runtime("external", port)})
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_secret_documents_are_phase_specific_and_bounded(self):
        for phase_name, valid in [("database", {"db_password": secrets()["db_password"]}), ("install", secrets()), ("checkpoint-ready", {"db_password": secrets()["db_password"]})]:
            expression = "cloudSecrets($p['secret'], $p['phase']); echo 'accepted';"
            payload = {"runtime": runtime(), "secret": valid, "phase": phase_name}
            self.assertEqual(self.php(expression, payload).returncode, 0)
            for invalid in [{}, dict(valid, jwt_secret="x" * 64), dict(valid, db_password="short"), dict(valid, db_password="x" * 1025), dict(valid, db_password="long-enough\npassword")]:
                result = self.php(expression, dict(payload, secret=invalid))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        result = self.php("cloudSecrets($p['secret'], 'database');", {"runtime": runtime(), "secret": secrets()})
        self.assertNotEqual(result.returncode, 0)

    def test_checkpoint_requires_no_config_no_tables_and_no_data(self):
        expression = "cloudCheckpointState($p['configured'],$p['tables'],$p['entries']); echo 'ready';"
        for configured, tables, entries, ready in [
            (False, 0, [], True), (True, 0, [], False), (False, 1, [], False),
            (False, 200, [], False), (False, 0, ['.ncdata'], False),
            (False, 0, ['.htaccess'], False), (False, 0, ['user-files'], False),
        ]:
            result = self.php(expression, {"runtime": runtime(), "configured": configured, "tables": tables, "entries": entries})
            self.assertEqual(result.returncode == 0, ready, result.stderr)
            self.assertEqual(result.stdout, 'ready' if ready else '')
        checkpoint = PHP_SOURCE.split('function cloudCheckpointReady(', 1)[1].split('\nfunction ', 1)[0]
        self.assertIn('SELECT COUNT(*) FROM information_schema.TABLES', checkpoint)
        for forbidden in ['->exec(', 'cloudBoot(', 'file_put_contents(', 'require $config']:
            self.assertNotIn(forbidden, checkpoint)
        self.assertIn('start_database_cache', INSTALL)

    def test_template_rendering_and_bounded_pools_for_all_tls_modes(self):
        for mode in ["acme", "provided", "external"]:
            for children in [3, 4, 8, 17, 512]:
                with self.subTest(mode=mode, children=children):
                    c = dict(runtime(mode, 8443), php_children=children)
                    payload = {"runtime": c, "templates": {p.name: p.read_text() for p in TEMPLATES.iterdir()}}
                    result = self.php("$out=[]; foreach ($p['templates'] as $name=>$text) { $out[$name]=cloudRender($text, $c); } echo json_encode($out, JSON_THROW_ON_ERROR);", payload)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn("@@", result.stdout)
                    rendered = json.loads(result.stdout)
                    pool = configparser.ConfigParser(interpolation=None)
                    pool.read_string(rendered["www.conf"])
                    self.assertEqual(pool.sections(), ["www", "office_callback"])
                    self.assertEqual(sum(int(pool[name]["pm.max_children"]) for name in pool.sections()), children)
                    self.assertEqual(int(pool["office_callback"]["pm.max_children"]), 2 if children >= 4 else 1)
                    self.assertNotEqual(pool["www"]["listen"], pool["office_callback"]["listen"])
                    for name in pool.sections():
                        section = pool[name]
                        self.assertGreaterEqual(int(section["pm.min_spare_servers"]), 1)
                        self.assertLessEqual(int(section["pm.min_spare_servers"]), int(section["pm.start_servers"]))
                        self.assertLessEqual(int(section["pm.start_servers"]), int(section["pm.max_spare_servers"]))
                        self.assertLessEqual(int(section["pm.max_spare_servers"]), int(section["pm.max_children"]))
                        self.assertEqual(section["php_admin_value[post_max_size]"], "10256M")
                        self.assertEqual(section["php_admin_value[memory_limit]"], str(c["php_memory_mb"]) + "M")
                        self.assertEqual(section["clear_env"], "yes")
                        self.assertEqual(section["security.limit_extensions"], ".php")
                        self.assertEqual(section["listen.mode"], "0660")
                        self.assertEqual(section["user"], "www")
                        self.assertEqual(section["rlimit_core"], "0")
                    for vhost in ("https.conf", "external.conf"):
                        handler = rendered[vhost].split('<FilesMatch "\\.php$">', 1)[1].split('</FilesMatch>', 1)[0]
                        self.assertIn("%{CONN_REMOTE_ADDR} == '10.77.0.6'", handler)
                        self.assertIn('office-callback.sock|fcgi://localhost/', handler)
                        self.assertIn('<Else>', handler)
                        self.assertIn('nextcloud.sock|fcgi://localhost/', handler)
                        self.assertNotIn('%{REMOTE_ADDR}', handler)
                        self.assertNotIn('X-Forwarded', handler)
                    if mode == "external":
                        active = rendered["httpd.conf"] + rendered["external.conf"]
                        for forbidden in ["Listen 443", "SSLEngine", "SSLCertificate", "LoadModule ssl_module", "SSLSessionCache"]:
                            self.assertNotIn(forbidden, active)
                        self.assertIn("Require ip 192.0.2.0/24 198.51.100.7/32 10.77.0.6", active)
                    else:
                        certdir = "/usr/local/etc/letsencrypt/live/cloud.example.com" if mode == "acme" else "/usr/local/etc/cloud-tls"
                        self.assertIn(certdir + "/fullchain.pem", rendered["https.conf"])
                        self.assertIn("https://cloud.example.com:8443%{REQUEST_URI}", rendered["https.conf"])

    def test_managed_fpm_patch_preserves_unmanaged_production_values(self):
        base = "; Package defaults\n[global]\npid = original.pid\nerror_log = original.log\nprocess.max = 12\ninclude = *.conf\n"
        overrides = template("php-fpm.conf")
        result = self.php("$text=cloudPatchIni($p['base'], $p['overrides']); echo json_encode(['text'=>$text,'parsed'=>parse_ini_string($text,true,INI_SCANNER_RAW)],JSON_THROW_ON_ERROR);", {"runtime": runtime(), "base": base, "overrides": overrides})
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertIn("; Package defaults", parsed["text"])
        self.assertEqual(parsed["parsed"]["global"]["process.max"], "12")
        self.assertEqual(parsed["parsed"]["global"]["include"], "/usr/local/etc/php-fpm.d/www.conf")
        self.assertEqual(parsed["parsed"]["global"]["pid"], "/var/run/php-fpm.pid")

    def test_managed_pool_patch_has_two_pools_without_extra_listeners(self):
        base = "; Package pool\n[www]\nuser = nobody\nlisten = 127.0.0.1:9000\npm = dynamic\n;pm.max_children = 5\n"
        result = self.php("echo cloudPatchIni($p['base'],cloudRender($p['overrides'],$c));", {
            "runtime": runtime(), "base": base, "overrides": template("www.conf")})
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = configparser.ConfigParser(interpolation=None)
        parsed.read_string(result.stdout)
        self.assertEqual(parsed.sections(), ["www", "office_callback"])
        self.assertNotIn("127.0.0.1:9000", result.stdout)
        self.assertIn("; Package pool", result.stdout)
        for name in parsed.sections():
            self.assertEqual(parsed[name]["user"], "www")
            self.assertTrue(parsed[name]["listen"].startswith("/var/run/php-fpm/"))

    def test_worker_refuses_single_web_worker_capacity(self):
        result = self.php("echo 'accepted';", {"runtime": dict(runtime(), php_children=2)})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_fpm_global_overrides_precede_pool_include_with_commented_defaults(self):
        base = "[global]\npid = original.pid\n;error_log = log/php-fpm.log\n;log_level = notice\n;daemonize = yes\ninclude=etc/php-fpm.d/*.conf\n"
        result = self.php("echo cloudPatchIni($p['base'], $p['overrides']);", {
            "runtime": runtime(), "base": base, "overrides": template("php-fpm.conf")})
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        includes = [i for i, line in enumerate(lines) if line.startswith("include = ")]
        self.assertEqual(len(includes), 1)
        for key in ("error_log", "log_level", "daemonize"):
            positions = [i for i, line in enumerate(lines) if line.startswith(key + " = ")]
            self.assertEqual(len(positions), 1)
            self.assertLess(positions[0], includes[0])

    def test_system_config_has_exact_proxy_trust_and_public_and_callback_urls(self):
        for mode in ["provided", "external"]:
            c = runtime(mode, 8443)
            result = self.php("echo json_encode(cloudSystemConfig($c),JSON_THROW_ON_ERROR);", {"runtime": c})
            self.assertEqual(result.returncode, 0, result.stderr)
            config = json.loads(result.stdout)
            self.assertEqual(config["overwrite.cli.url"], c["public_url"])
            self.assertEqual(config["overwritehost"], "cloud.example.com:8443")
            self.assertEqual(config["overwriteprotocol"], "https")
            self.assertEqual(config["trusted_proxies"], c["proxy_networks"])
            self.assertEqual(config["forwarded_for_headers"], ["HTTP_X_FORWARDED_FOR"])
            self.assertEqual("10.77.0.2" in config["trusted_domains"], mode == "external")
            self.assertNotIn("10.77.0.6", config["trusted_proxies"])
            self.assertTrue(config["upgrade.disable-web"])
            self.assertEqual(config["mail_smtpmode"], "null")
            self.assertEqual(config["memcache.locking"], "\\OC\\Memcache\\Redis")
            self.assertNotIn("verify_peer_off", config)
            self.assertEqual([p["writable"] for p in config["apps_paths"]], [False, True])

    def test_connector_requires_exact_urls_8081_and_verified_tls(self):
        for mode in ["provided", "external"]:
            c = runtime(mode, 8443)
            good = connector(c)
            expression = "cloudConnector($p['connector'], $c); echo 'accepted';"
            self.assertEqual(self.php(expression, {"runtime": c, "connector": good}).returncode, 0)
            for key, value in [("StorageUrl", c["public_url"]), ("DocumentServerInternalUrl", "http://10.77.0.6:8080/"), ("DocumentServerInternalUrl", "http://10.77.0.6:8081/?bad=1"), ("DocumentServerInternalUrl", "http://127.0.0.1:8081/"), ("DocumentServerUrl", "https://cloud.example.com/onlyoffice/"), ("jwt_secret", "short"), ("verify_peer_off", "true")]:
                invalid = {"apps": {"onlyoffice": dict(good["apps"]["onlyoffice"], **{key: value})}}
                result = self.php(expression, {"runtime": c, "connector": invalid})
                self.assertNotEqual(result.returncode, 0, (key, value))
                self.assertEqual(result.stdout, "")
            for invalid in [dict(good, system={"debug": True}), {"apps": {"onlyoffice": good["apps"]["onlyoffice"], "other": {}}}, {"apps": []}]:
                self.assertNotEqual(self.php(expression, {"runtime": c, "connector": invalid}).returncode, 0)

    def test_install_recovery_requires_empty_db_or_a_complete_matching_instance(self):
        expression = "$app=$p['app']; if ($p['identity']) $app['cloud_installer_identity']=cloudIdentity($c); echo cloudInstallDecision($c,$app,$p['tables'],$p['entries'],$p['admin']);"
        complete = {"installed": True, "maintenance": False, "version": "35.0.0.1", "dbname": "nextcloud", "dbuser": "nextcloud", "dbhost": "127.0.0.1", "dbtype": "mysql", "dbtableprefix": "oc_", "datadirectory": "/var/nc-data", "overwrite.cli.url": runtime()["public_url"], "trusted_domains": ["cloud.example.com"], "instanceid": "oc123456"}
        base = {"runtime": runtime(), "app": {}, "identity": False, "tables": 0, "entries": [], "admin": False}
        for update, expected in [
            ({}, "fresh"),
            ({"app": {"installed": False}, "identity": True, "entries": [".htaccess", "index.html"]}, "fresh"),
            ({"app": complete, "identity": True, "tables": 200, "entries": [".ncdata", "cloudadmin"], "admin": True}, "installed"),
            ({"tables": 1}, None),
            ({"app": {"installed": False}, "identity": True, "tables": 200}, None),
            ({"entries": ["unowned-data"]}, None),
            ({"app": {"installed": False}, "identity": True, "entries": [".ncdata"]}, None),
            ({"app": complete, "identity": False, "tables": 200, "entries": [".ncdata"], "admin": True}, None),
            ({"app": complete, "identity": True, "tables": 200, "entries": [".ncdata"], "admin": False}, None),
            ({"app": dict(complete, maintenance=True), "identity": True, "tables": 200, "entries": [".ncdata"], "admin": True}, None),
            ({"app": dict(complete, version="35.0.1.1"), "identity": True, "tables": 200, "entries": [".ncdata"], "admin": True}, None),
            ({"app": dict(complete, trusted_domains=["other.example.com"]), "identity": True, "tables": 200, "entries": [".ncdata"], "admin": True}, None),
        ]:
            with self.subTest(update=update):
                result = self.php(expression, dict(base, **update))
                self.assertEqual(result.returncode == 0, expected is not None, result.stderr)
                self.assertEqual(result.stdout, expected or "")
                if update.get("tables") == 1:
                    self.assertIn("checkpoint", result.stderr)

    def test_code_identity_reads_version_without_executing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            for name in ["occ", ".htaccess", "lib/base.php", "3rdparty/autoload.php", "core/signature.json"]:
                target = app / name
                target.parent.mkdir(exist_ok=True)
                target.write_text("fixture")
            for selected, version, accepted in [("35.0.0", "array(35,0,0,1)", True),
                                                ("35.0.0", "[35, 1, 2, 3]", False),
                                                ("36.1.2", "[36, 1, 2, 3]", True),
                                                ("35.0.0", "array(34,0,0,1)", False),
                                                ("35.0.0", "array(35,0,0,1,2)", False)]:
                c = runtime()
                c["versions"]["nextcloud"] = selected
                (app / "version.php").write_text("<?php $OC_Version = " + version + "; $OC_VersionString = '" + selected + "'; file_put_contents(" + json.dumps(str(app / "executed")) + ", 'bad');")
                result = self.php("echo cloudCode($c,$p['path']);", {"runtime": c, "path": tmp})
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertFalse((app / "executed").exists())
            for public in ("35.0.0 RC2", "35.0.0beta1", "35.0.1", ""):
                (app / "version.php").write_text("<?php $OC_Version = [35,0,0,1]; $OC_VersionString = '" + public + "';")
                self.assertNotEqual(self.php("cloudCode($c,$p['path']);", {"runtime": runtime(), "path": tmp}).returncode, 0)
            (app / "core/signature.json").unlink()
            self.assertNotEqual(self.php("cloudCode($c,$p['path']);", {"runtime": runtime(), "path": tmp}).returncode, 0)

    def test_database_retry_checks_credentials_before_alter_and_never_outputs_sql(self):
        # A PDO stand-in exercises actual account logic without a server/socket.
        fake = r'''
class TestStatement extends PDOStatement {
    public function __construct(private mixed $value) {}
    public function fetchColumn(int $column = 0): mixed { return $this->value; }
    public function fetch(int $mode = PDO::FETCH_DEFAULT, int $orientation = PDO::FETCH_ORI_NEXT, int $offset = 0): mixed { return $this->value; }
    public function fetchAll(int $mode = PDO::FETCH_DEFAULT, mixed ...$args): array { return $this->value; }
}
class TestDatabase extends PDO {
    public array $statements = [];
    public function __construct(private mixed $account, private array $grants) {}
    public function exec(string $statement): int|false { $this->statements[]=$statement; return 0; }
    public function query(string $query, ?int $fetchMode = null, mixed ...$args): PDOStatement|false {
        if ($query==='SELECT VERSION()') return new TestStatement('12.3.1-MariaDB');
        if (str_starts_with($query,'SELECT plugin')) return new TestStatement($this->account);
        if (str_starts_with($query,'SHOW GRANTS')) return new TestStatement($this->grants);
        if (str_starts_with($query,'SELECT DEFAULT_COLLATION')) return new TestStatement('utf8mb4_bin');
        if (str_starts_with($query,'SELECT User')) return new TestStatement([]);
        throw new RuntimeException('Unexpected query');
    }
}
$db=new TestDatabase($p['account'],$p['grants']);
try { cloudEnsureDatabase($c,$db,$p['password']); $ok=true; } catch (Throwable $e) { $ok=false; }
echo json_encode(['ok'=>$ok,'statements'=>$db->statements],JSON_THROW_ON_ERROR);
'''
        password = secrets()["db_password"]
        verifier = "*" + hashlib.sha1(hashlib.sha1(password.encode()).digest()).hexdigest().upper()
        account = {"plugin": "mysql_native_password", "authentication_string": verifier}
        for actual, grants, expected in [
            (False, [], True),
            (account, ["GRANT USAGE ON *.* TO 'nextcloud'@'127.0.0.1'", "GRANT SELECT ON `nextcloud`.* TO 'nextcloud'@'127.0.0.1'"], True),
            (dict(account, authentication_string="*WRONG"), [], False),
            (account, ["GRANT ALL PRIVILEGES ON *.* TO 'nextcloud'@'127.0.0.1'"], False),
            (account, ["GRANT ALL PRIVILEGES ON `nextcloud`.* TO 'nextcloud'@'127.0.0.1' WITH GRANT OPTION"], False),
        ]:
            result = self.php(fake, {"runtime": runtime(), "password": password, "account": actual, "grants": grants})
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output["ok"], expected)
            statements = output["statements"]
            self.assertEqual(statements[:3], ["SET SESSION sql_log_bin=0", "SET SESSION sql_log_off=1", "SET SESSION long_query_time=31536000"])
            self.assertNotIn(password, "\n".join(statements))
            if expected:
                self.assertTrue(any("CREATE USER IF NOT EXISTS" in s for s in statements))
                self.assertTrue(any("ALTER USER 'nextcloud'" in s and verifier in s for s in statements))
                self.assertTrue(any("GRANT SELECT" in s and "ON `nextcloud`.*" in s for s in statements))
            else:
                self.assertEqual(len(statements), 3)

    def test_diagnostics_never_reveal_raw_exception_messages_or_credentials(self):
        payload = {"runtime": runtime(), "message": json.dumps(secrets()) + " SQL *HASH " + connector(runtime())["apps"]["onlyoffice"]["jwt_secret"]}
        result = self.php("throw new RuntimeException($p['message']);", payload)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("Raw exception output was suppressed", result.stderr)
        for text in ["SQL", "*HASH", *secrets().values()]:
            self.assertNotIn(text, result.stderr)
        result = self.php("echo cloudRender('@@ADMIN_PASSWORD@@', $c);")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
