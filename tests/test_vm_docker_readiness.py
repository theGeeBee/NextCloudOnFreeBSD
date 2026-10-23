"""Docker service PID is not yet proof of a ready engine API; no Docker invoked."""
import contextlib
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE=(Path(__file__).resolve().parents[1]/'resources/vm/bootstrap.sh').read_text()
PROGRAM=SOURCE.split("<<'PY_DOCKER_READY'\n",1)[1].split('\nPY_DOCKER_READY\n',1)[0]


class DockerReadinessTests(unittest.TestCase):
    def run_program(self,results):
        clock=[0];out=io.StringIO()
        def pause(seconds):clock[0]+=seconds
        with patch('time.monotonic',side_effect=lambda:clock[0]),patch('time.sleep',side_effect=pause), \
                patch('subprocess.run',side_effect=results) as native,contextlib.redirect_stdout(out):
            exec(compile(PROGRAM,'guest-docker-api-readiness','exec'),{})
        return out.getvalue(),native,clock[0]

    def test_delayed_api_and_empty_server_version_are_not_completion(self):
        out,native,elapsed=self.run_program([
            SimpleNamespace(returncode=1,stdout='\n',stderr='private-native-error'),
            SimpleNamespace(returncode=0,stdout='\n',stderr=''),
            SimpleNamespace(returncode=0,stdout='29.8.2\n',stderr='')])
        self.assertEqual(out,'29.8.2\n');self.assertEqual(elapsed,2)
        self.assertEqual(native.call_count,3)
        for call in native.call_args_list:
            self.assertEqual(call.args[0],['docker','--host=unix:///var/run/docker.sock','version','--format','{{.Server.Version}}'])
            self.assertTrue(call.kwargs['capture_output']);self.assertEqual(call.kwargs['timeout'],5)

    def test_transient_socket_error_or_query_timeout_is_bounded_and_retryable(self):
        out,_,elapsed=self.run_program([OSError('private-socket-error'),subprocess.TimeoutExpired(['docker'],5),
                                       SimpleNamespace(returncode=0,stdout='29.8.2',stderr='')])
        self.assertEqual(out,'29.8.2\n');self.assertEqual(elapsed,2)

    def test_permanently_missing_api_or_invalid_version_never_completes(self):
        for value in ('','29.8.2-rc1','private-error'):
            with self.subTest(value=value),self.assertRaisesRegex(SystemExit,'bounded startup wait'):
                self.run_program(lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout=value,stderr=''))

    def test_readiness_and_private_logging_precede_saved_inventory_receipt(self):
        initial=SOURCE.index('[ "$decision" = initial ]')
        log=SOURCE.index('exec >> "$LOG" 2>&1')
        apk=SOURCE.index('env -i PATH="$PATH" apk add')
        ready=SOURCE.index("<<'PY_DOCKER_READY'")
        save=SOURCE.index('printf \'%s\\n\' "$docker_version"')
        complete=SOURCE.index("<<'PY_COMPLETE'")
        self.assertLess(initial,log);self.assertLess(log,apk);self.assertLess(ready,save);self.assertLess(save,complete)
        self.assertIn('0:600:1',SOURCE)
