"""Offline cron fence checks; all service/process/spool observations are modeled."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PHP = shutil.which("php")
HELPER = ROOT / "resources/jails/nextcloud-cron-fence.php"
WORKER = (ROOT / "resources/jails/nextcloud.sh").read_text()


def function(name):
    single = re.search(r"(?m)^" + name + r"\(\) \{[^\n]*\}$", WORKER)
    if single:
        return single[0]
    return re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}(?=\n(?:\n|trap)|\Z)", WORKER)[0]


@unittest.skipUnless(PHP, "PHP unavailable")
class ClosureTests(unittest.TestCase):
    def php(self, body, data):
        code = "require " + json.dumps(str(HELPER)) + "; $p=json_decode(stream_get_contents(STDIN),true); "
        code += "try { " + body + " } catch (Throwable $e) { echo 'refused'; }"
        result = subprocess.run([PHP, "-d", "display_errors=0", "-r", code], input=json.dumps(data),
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout

    def rows(self):
        return "10 0 0 init\n20 10 0 sh\n21 20 0 php\n22 21 0 ps\n30 10 80 httpd\n31 10 80 php-fpm\n40 10 88 mariadbd\n50 10 6379 redis-server\n"

    def closed(self, text, args=""):
        return self.php("echo cronWritersClosed(cronProcesses($p['rows']),20,21,"
                        "['www'=>80,'mysql'=>88,'redis'=>6379],fn($a)=>[0,$p['args'],'']) ? 'closed' : 'busy';",
                        {"rows": text, "args": args})

    def test_exact_worker_ancestry_and_services(self):
        self.assertEqual(self.closed(self.rows()), "closed")
        for extra in ("60 10 80 php", "60 10 0 sh", "60 10 0 cron", "60 10 0 sleep",
                      "60 20 0 sh", "60 10 0 ps", "60 10 0 sshd", "60 10 0 unknown"):
            with self.subTest(extra=extra):
                self.assertEqual(self.closed(self.rows() + extra + "\n"), "busy")

    def test_wrong_ancestry_uid_duplicate_and_bad_inventory_refuse(self):
        for rows in (self.rows().replace("21 20", "21 10"), self.rows().replace("20 10 0", "20 10 80"),
                     self.rows() + "21 20 0 php\n", "", self.rows() + "unknown\n",
                     self.rows().replace("10 0", "10 21")):
            self.assertEqual(self.closed(rows), "refused")

    def test_database_shell_requires_exact_script_and_database_child(self):
        rows = self.rows().replace("40 10", "40 39") + "39 10 0 sh\n"
        self.assertEqual(self.closed(rows, "/bin/sh /usr/local/bin/mariadbd-safe --user=mysql"), "closed")
        for args in ("/bin/sh /tmp/mariadbd-safe", "/bin/sh /usr/local/bin/mariadbd-safe-evil", "secret sentinel"):
            self.assertEqual(self.closed(rows, args), "busy")
        self.assertEqual(self.closed(self.rows() + "39 10 0 sh\n", "/bin/sh /usr/local/bin/mariadbd-safe"), "busy")

    def test_scanners_require_selected_exact_pid_uid_name_and_binary(self):
        scanners = {"60": {"uid": 106, "name": "clamd"}, "61": {"uid": 106, "name": "freshclam"}}
        rows = self.rows() + "60 10 106 clamd\n61 10 106 freshclam\n"
        args = {"60": "/usr/local/sbin/clamd", "61": "/usr/local/bin/freshclam --daemon -p /var/run/clamav/freshclam.pid"}
        body = "echo cronWritersClosed(cronProcesses($p['rows']),20,21,"
        body += "['www'=>80,'mysql'=>88,'redis'=>6379],function($a)use($p){"
        body += "return [$p['code'],$p['args'][$a[3]],$p['error']];},$p['scanners']) ? 'closed' : 'busy';"
        data = dict(rows=rows, args=args, scanners=scanners, code=0, error="")
        self.assertEqual(self.php(body, data), "closed")
        self.assertEqual(self.closed(rows), "busy")
        for update in (
            {"rows": rows.replace("60 10 106", "60 10 0")},
            {"rows": rows.replace("60 10 106", "60 10 107")},
            {"rows": rows.replace("60 10 106 clamd", "60 10 106 php")},
            {"rows": rows.replace("60 10 106 clamd", "60 10 106 sh")},
            {"rows": rows.replace("60 10 106 clamd\n", "")},
            {"rows": rows.replace("60 10 106", "62 10 106")},
            {"rows": rows + "62 10 106 clamd\n"},
            {"rows": rows + "62 10 106 php\n"},
            {"rows": rows + "62 10 0 sh\n"},
            {"args": {**args, "60": "/tmp/clamd"}},
            {"args": {**args, "60": "/usr/local/sbin/clamd --config-file=/tmp/foreign"}},
            {"args": {**args, "61": "/usr/local/bin/freshclam -d --config-file=/tmp/foreign"}},
            {"code": 1}, {"error": "failed"},
        ):
            with self.subTest(update=update):
                self.assertEqual(self.php(body, {**data, **update}), "busy")

    def test_scanner_pidfile_metadata_content_and_stability(self):
        body = "$stat=function($path)use(&$calls,$p){"
        body += "if(str_ends_with($path,'.pid')) { $calls++; return array_replace($p['file'],"
        body += "$calls===2 ? $p['changed'] : []); }"
        body += "return ['mode'=>($path===$p['badparent'] ? 0120755 : 0040755),"
        body += "'uid'=>($path===$p['foreignparent'] ? 106 : 0)];}; $calls=0;"
        body += "echo json_encode(cronScannerPids(106,$stat,fn($path)=>str_contains($path,'/clamd.') ? $p['text'] : '61'.chr(10)));"
        file = dict(mode=0o100644, uid=106, nlink=1, size=3, ino=12, dev=1, gid=106, mtime=1, ctime=1)
        data = dict(file=file, text="60\n", changed={}, badparent="", foreignparent="")
        self.assertEqual(set(json.loads(self.php(body, data))), {"60", "61"})
        self.assertEqual(set(json.loads(self.php(body, {**data, "file": {**file, "uid": 0}}))), {"60", "61"})
        for update in ({"uid": 80}, {"mode": 0o100666}, {"mode": 0o120644},
                       {"mode": 0o040755}, {"nlink": 2}, {"size": 33}, {"size": 0}):
            self.assertEqual(self.php(body, {**data, "file": {**file, **update}}), "refused")
        for text in ("0\n", "-1\n", "60 61\n", "60\n61\n", "60x", "61\n", ""):
            self.assertEqual(self.php(body, {**data, "text": text}), "refused")
        for changed in ({"ino": 13}, {"uid": 0}, {"mtime": 2}, {"size": 2}):
            self.assertEqual(self.php(body, {**data, "changed": changed}), "refused")
        for path in ("/", "/var", "/var/run", "/var/run/clamav"):
            self.assertEqual(self.php(body, {**data, "badparent": path}), "refused")
        self.assertEqual(self.php(body, {**data, "foreignparent": "/var/run"}), "refused")

    def test_scanner_pidfile_missing_or_changed_during_inventory_refuses(self):
        missing = "echo json_encode(cronScannerPids(106,fn($path)=>str_ends_with($path,'.pid') ? false : ['mode'=>0040755,'uid'=>0],fn($path)=>'60'.chr(10)));"
        self.assertEqual(self.php(missing, {}), "refused")
        body = "$calls=0; $tick=0; cronWaitClosed(20,21,['www'=>80,'mysql'=>88,'redis'=>6379],"
        body += "fn($a)=>[0,$p['rows'],''],function()use(&$tick){return $tick++ * 60;},fn()=>null,"
        body += "function()use(&$calls,$p){return [60=>['uid'=>106,'name'=>'clamd','file'=>++$calls]];}); echo 'closed';"
        # No scanner PID in the inventory may be silently treated as stopped.
        self.assertEqual(self.php(body, {"rows": self.rows()}), "refused")

    def test_selected_scanner_wait_rechecks_pidfile_and_command_contracts(self):
        body = "$calls=0; $tick=0; $commands=[]; cronWaitClosed(20,21,['www'=>80,'mysql'=>88,'redis'=>6379],"
        body += "function($a)use(&$commands,$p){$commands[]=$a; return [0,$a[1]==='-ax' ? $p['rows'] : "
        body += "($a[3]==='60' ? '/usr/local/sbin/clamd' : '/usr/local/bin/freshclam --daemon -p /var/run/clamav/freshclam.pid'),''];},"
        body += "function()use(&$tick){return $tick++ * 60;},fn()=>null,"
        body += "function()use(&$calls,$p){$calls++; return [60=>['uid'=>106,'name'=>'clamd','file'=>$p['changed'] ? $calls : 1],"
        body += "61=>['uid'=>106,'name'=>'freshclam','file'=>1]];}); echo json_encode([$calls,$commands]);"
        rows = self.rows() + "60 10 106 clamd\n61 10 106 freshclam\n"
        calls, commands = json.loads(self.php(body, {"rows": rows, "changed": False}))
        self.assertEqual(calls, 2)
        self.assertEqual(commands, [
            ['/bin/ps', '-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'uid=', '-o', 'comm='],
            ['/bin/ps', '-ww', '-p', '60', '-o', 'args='],
            ['/bin/ps', '-ww', '-p', '61', '-o', 'args='],
        ])
        self.assertEqual(self.php(body, {"rows": rows, "changed": True}), "refused")

    def test_bounded_wait_and_command_failure(self):
        body = "$tick=0; $calls=0; cronWaitClosed(20,21,['www'=>80,'mysql'=>88,'redis'=>6379],"
        body += "function($a)use(&$calls,$p){$calls++;return [$p['code'],$p['rows'],''];},"
        body += "function()use(&$tick){return $tick++ * 30;},fn()=>null); echo 'closed';"
        self.assertEqual(self.php(body, {"code": 0, "rows": self.rows()}), "closed")
        self.assertEqual(self.php(body, {"code": 0, "rows": self.rows() + "60 10 0 sh\n"}), "refused")
        self.assertEqual(self.php(body, {"code": 1, "rows": self.rows()}), "refused")

    def test_pending_launcher_must_disappear_before_success(self):
        body = "$calls=0; cronWaitClosed(20,21,['www'=>80,'mysql'=>88,'redis'=>6379],"
        body += "function($a)use(&$calls,$p){return [0,$p['rows'].(++$calls===1 ? '60 10 0 sh' : ''),''];},"
        body += "fn()=>0,fn()=>null); echo $calls;"
        self.assertEqual(self.php(body, {"rows": self.rows()}), "2")

    def test_spool_listing_exact_or_proven_absent_only(self):
        body = "echo cronTableState($p['before'],$p['after'],$p['result'],'template');"
        metadata = {"ino": 12, "uid": 0}
        for before, after, result, expected in (
            (None, None, [1, "", "crontab: no crontab for www\n"], "absent"),
            (metadata, metadata, [0, "template", ""], "present"),
            (None, None, [1, "", "permission denied"], "refused"),
            (None, None, [0, "", ""], "refused"),
            (metadata, metadata, [0, "template\nunrelated job", ""], "refused"),
            (metadata, metadata, [1, "", "crontab: no crontab for www\n"], "refused"),
            (None, metadata, [0, "template", ""], "refused"),
            (metadata, {"ino": 13, "uid": 0}, [0, "template", ""], "refused"),
        ):
            with self.subTest(result=result):
                self.assertEqual(self.php(body, dict(before=before, after=after, result=result)), expected)

    def test_spool_owner_modes_links_and_ancestry(self):
        body = "$stat=function($path)use($p){return $path==='/var/cron/tabs/www' ? $p['file'] : "
        body += "['mode'=>($path===$p['badparent'] ? 0120700 : 0040700),'uid'=>0];}; "
        body += "echo cronTableMetadata('', $stat, fn($p)=>['.','..','www']) ? 'valid' : 'absent';"
        file = dict(mode=0o100600, uid=0, nlink=1, size=100, ino=12)
        self.assertEqual(self.php(body, dict(file=file, badparent="")), "valid")
        for update in ({"uid": 80}, {"mode": 0o100644}, {"mode": 0o120600}, {"nlink": 2}, {"size": 65537}):
            self.assertEqual(self.php(body, dict(file={**file, **update}, badparent="")), "refused")
        self.assertEqual(self.php(body, dict(file=file, badparent="/var/cron")), "refused")

    def test_extra_user_spools_are_preserved_and_refused_before_activation(self):
        body = "$stat=fn($path)=>['mode'=>0040700,'uid'=>0]; "
        body += "echo cronTableMetadata('', $stat, fn($path)=>$p['names']) === null ? 'absent' : 'present';"
        self.assertEqual(self.php(body, {'names':['.','..']}), 'absent')
        for names in (['.','..','root'],['.','..','www','operator'],[],['.','..','www','www']):
            self.assertEqual(self.php(body, {'names':names}), 'refused')

    def test_process_command_uses_native_repeated_empty_header_fields(self):
        self.assertIn("['/bin/ps', '-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'uid=', '-o', 'comm=']", HELPER.read_text())


class FinishTests(unittest.TestCase):
    def test_prepare_closes_base_cron_and_initial_diagnostics_are_private(self):
        prepare = function("prepare")
        self.assertLess(prepare.index("close_cron"), prepare.index('if [ -f "$STATE/nextcloud-prepared" ]'))
        self.assertIn("cron_enable=NO", prepare)
        self.assertNotIn("cron_enable=YES", prepare)
        finish = function("finish")
        self.assertIn('php -f "$APP/cron.php" < /dev/null >> "$STATE/nextcloud-finish.log"', finish)
        self.assertNotIn("/var/log/nextcloud/cron.log", finish)

    def run_finish(self, *, table="absent", failure="", pending=False, apps="", backend="onlyoffice"):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            for name, value in (("table", table), ("daemon", "yes"), ("boot", "YES")):
                (path / name).write_text(value)
            script = "set -eu\n" + f"STATE={shlex.quote(temp)}\n"
            script += 'APP=$STATE/app; PAYLOAD=$STATE; TEMPLATES=$STATE; RUNTIME=$STATE/runtime; HELPER=helper; stage=; cron_fenced=0; antivirus_active=0\n'
            script += 'version_office_backend='+shlex.quote(backend)+'\n'
            script += 'failure=' + shlex.quote(failure) + '\npending=' + str(int(pending)) + '\n'
            script += 'apps=' + shlex.quote(apps) + '\n'
            script += r'''
event() { printf '%s\n' "$1" >> "$STATE/events"; [ "$failure" != "$1" ]; }
fail() { exit 1; }
sysrc() {
    case "$*" in
        '-n cron_enable') cat "$STATE/boot" ;;
        'cron_enable=NO') event disable; printf NO > "$STATE/boot" ;;
        'cron_enable=YES') event enable; printf YES > "$STATE/boot" ;;
        'clamav_clamd_enable=YES clamav_freshclam_enable=YES'|'clamav_clamd_enable=NO clamav_freshclam_enable=NO') event scanners-boot ;;
        *) exit 90 ;;
    esac
}
service() {
    case "$*" in
        'cron onestatus'|'cron status') [ "$(cat "$STATE/daemon")" = yes ] ;;
        'cron onestop') event stop; printf no > "$STATE/daemon" ;;
        'cron start') event start || return 1; printf yes > "$STATE/daemon" ;;
        *) event service ;;
    esac
}
cron_check() {
    case "$1" in
        closed) event closed || return 1; event "fence:$#:${3-}"; [ "$(cat "$STATE/daemon")" = no ] || return 1; [ "$pending" = 0 ] ;;
        table) event table || return 1; value=$(cat "$STATE/table"); [ "$value" != unknown ] || return 1; printf '%s\n' "$value" ;;
        *) exit 91 ;;
    esac
}
crontab() { event publish; printf present > "$STATE/table"; }
require_phase() { :; }
json() {
 case "$1:${2-}" in
  apps:*) printf '%s\n' "$apps" ;;
  get:onlyoffice_ip) printf 10.77.0.6 ;;
  get:storage_url) printf https://cloud.example.test/ ;;
  get:public_url) printf https://cloud.example.test/ ;;
  *) : ;;
 esac
}
optional_app_state() { if [ -f "$STATE/app-state" ]; then cat "$STATE/app-state"; else printf missing; fi; }
private_file() { :; }
configure_antivirus() { antivirus_active=1; event scanner; }
antivirus_app_config() { :; }
install() { :; }
apachectl() { :; }
find() { event permissions; }
chmod() { :; }
touch() { event marker; }
installed_check() { event installed; }
occ() {
    event "occ:$*" || return 1
    case "$1" in app:install|app:enable) printf enabled > "$STATE/app-state" ;; esac
    case "$*" in
      'config:app:get richdocuments wopi_url') printf http://10.77.0.6:8081/collabora/ ;;
      'config:app:get richdocuments wopi_callback_url') printf https://cloud.example.test/ ;;
      'config:app:get richdocuments public_wopi_url') if [ "$failure" = code-public-mismatch ]; then printf https://wrong.example; else printf https://cloud.example.test; fi ;;
      'config:app:get richdocuments wopi_allowlist') printf 10.77.0.6/32 ;;
    esac
}
mdo() {
    case "$*" in
        *connector-install*) event connector ;;
        *connector-import*) event import ;;
        *cron.php*) event initial || return 1; [ "$(cat "$STATE/daemon")" = no ] || return 1; [ "$(cat "$STATE/boot")" = NO ] ;;
        *) exit 92 ;;
    esac
}
'''
            (path / "runtime").write_text("{}")
            (path / "connector.json").write_text("{}")
            for name in ("cleanup", "start_service", "close_cron", "cron_closed", "app_progress", "install_optional_apps", "finish"):
                script += function(name).replace('/usr/local/bin/python3', shlex.quote(sys.executable)) + "\n"
            script += "trap cleanup EXIT\ntrap 'exit 1' HUP INT TERM\nfinish\n"
            result = subprocess.run(["sh", "-c", script], input="", text=True, capture_output=True)
            return (result.returncode, (path / "events").read_text().splitlines(),
                    (path / "table").read_text(), (path / "boot").read_text(), (path / "daemon").read_text())

    def test_fresh_and_resume_close_before_work_and_activate_after_checks(self):
        for table in ("absent", "present"):
            code, events, final, boot, daemon = self.run_finish(table=table)
            self.assertEqual(code, 0, events)
            self.assertEqual((final, boot, daemon), ("present", "YES", "yes"))
            self.assertLess(events.index("stop"), events.index("connector"))
            self.assertLess(events.index("initial"), events.index("permissions"))
            self.assertLess(events.index("installed"), events.index("enable"))
            self.assertEqual(events.count("publish"), int(table == "absent"))

    def test_finish_selects_scanner_exception_only_after_antivirus_configuration(self):
        for apps in ("", "files_antivirus"):
            code, events, table, boot, daemon = self.run_finish(apps=apps)
            self.assertEqual(code, 0, events)
            fences = [event for event in events if event.startswith("fence:")]
            self.assertEqual(fences, ["fence:2:"] + (["fence:3:--antivirus"] * 2 if apps else ["fence:2:"] * 2))

    def test_euro_finish_checks_selected_connector_before_initial_job_and_cron_enable(self):
        for failure in ('','import','occ:eurooffice:documentserver --check'):
            with self.subTest(failure=failure):
                code,events,table,boot,daemon=self.run_finish(backend='eurooffice',table='present',failure=failure)
                if failure:
                    self.assertNotEqual(code,0)
                    self.assertNotIn('initial',events)
                    self.assertEqual((table,boot,daemon),('present','NO','no'))
                else:
                    self.assertEqual(code,0,events)
                    self.assertEqual((table,boot,daemon),('present','YES','yes'))
                    self.assertLess(events.index('connector'),events.index('import'))
                    self.assertLess(events.index('occ:eurooffice:documentserver --check'),events.index('initial'))
                    self.assertNotIn('occ:onlyoffice:documentserver --check',events)

    def test_code_explicit_activation_and_discovery_postcondition_before_scheduling(self):
        activation='occ:richdocuments:activate-config --wopi-url http://10.77.0.6:8081/collabora/ --callback-url https://cloud.example.test/'
        for failure in ('',activation,'code-public-mismatch'):
            with self.subTest(failure=failure):
                code,events,table,boot,daemon=self.run_finish(backend='collabora',table='present',failure=failure)
                if failure:
                    self.assertNotEqual(code,0)
                    self.assertNotIn('initial',events)
                    self.assertEqual((table,boot,daemon),('present','NO','no'))
                else:
                    self.assertEqual(code,0,events)
                    self.assertLess(events.index(activation),events.index('initial'))
                    self.assertIn('occ:config:app:get richdocuments public_wopi_url',events)
                    self.assertEqual((table,boot,daemon),('present','YES','yes'))

    def test_every_failure_keeps_scheduling_closed_and_preserves_existing_table(self):
        for failure in ("closed", "connector", "import", "occ:onlyoffice:documentserver --check",
                        "occ:background:cron", "initial", "permissions", "installed", "enable", "start", "marker"):
            with self.subTest(failure=failure):
                code, events, table, boot, daemon = self.run_finish(table="present", failure=failure)
                self.assertNotEqual(code, 0, events)
                self.assertEqual((table, boot, daemon), ("present", "NO", "no"))
                self.assertEqual(events.count("initial"), int(failure not in (
                    "closed", "connector", "import", "occ:onlyoffice:documentserver --check", "occ:background:cron")))

    def test_unknown_schedule_or_pending_launcher_blocks_initial_run(self):
        for settings in ({"table": "unknown"}, {"pending": True}):
            code, events, table, boot, daemon = self.run_finish(**settings)
            self.assertNotEqual(code, 0)
            self.assertNotIn("initial", events)
            self.assertNotIn("publish", events)
            self.assertEqual((boot, daemon), ("NO", "no"))
            if "table" in settings:
                self.assertEqual(table, settings["table"])

    def test_optional_app_failure_keeps_cron_closed_before_initial_job(self):
        code, events, table, boot, daemon = self.run_finish(
            table="present", apps="notes", failure="occ:app:install notes")
        self.assertNotEqual(code, 0)
        self.assertIn("occ:app:install notes", events)
        self.assertNotIn("initial", events)
        self.assertNotIn("enable", events)
        self.assertEqual((table, boot, daemon), ("present", "NO", "no"))

    def test_integrate_holds_database_guard_around_entire_operation(self):
        from installer.deploy import Deployment
        deployment = object.__new__(Deployment)
        events = []

        @contextmanager
        def guard(actual):
            self.assertIs(actual, deployment)
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")

        with patch("installer.operations._database_guard", guard), patch.object(
                deployment, "_integrate", side_effect=lambda: events.append("integrate")):
            deployment.integrate()
        self.assertEqual(events, ["lock", "integrate", "unlock"])
        events.clear()
        with patch("installer.operations._database_guard", guard), patch.object(
                deployment, "_integrate", side_effect=RuntimeError("failed")):
            with self.assertRaises(RuntimeError):
                deployment.integrate()
        self.assertEqual(events, ["lock", "unlock"])
