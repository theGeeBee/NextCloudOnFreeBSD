"""Internal Euro finish seams; public profile gates and native acceptance unchanged."""
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer.config import Config
from installer.deploy import Deployment
from installer.office_vm import vm_connector_settings
import nextcloud_worker_fixtures as fixtures
from test_vm_worker_contract import payload


class EuroFinishOrchestrationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='euro-finish-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.enterContext(patch.object(Config,'bastille_root',new_callable=PropertyMock,return_value=str(self.root/'bastille')))
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.d=object.__new__(Deployment);self.d.config=self.c;self.d.secrets={'jwt_secret':'c'*64}
        self.d.jail=Mock(return_value=SimpleNamespace(returncode=0,stdout=''))
        self.target={'state':'Running (123)'}
        self.identity=self.enterContext(patch('installer.office_vm.native_vm_identity',return_value=self.target))
        self.network=self.enterContext(patch('installer.office_vm._vm_network_ready'))
        (self.d.jail_root(self.c.nextcloud_jail)/'root/cloud-installer').mkdir(parents=True,mode=0o700)

    def test_vm_health_from_nc_precedes_proxy_and_secret_import_into_selected_app(self):
        self.d._integrate()
        self.identity.assert_called_once_with(self.d)
        self.network.assert_called_once_with(self.d,self.target)
        health,finish=self.d.jail.call_args_list
        self.assertEqual(health.args[:2],(self.c.nextcloud_jail,'python3'))
        self.assertEqual(health.args[-1],'http://'+self.c.onlyoffice_ip+':8081/healthcheck')
        self.assertNotIn('c'*64,repr(health))
        self.assertEqual(finish.args,(self.c.nextcloud_jail,'/bin/sh','/root/cloud-installer/resources/jails/nextcloud.sh','finish'))
        self.assertEqual(json.loads(finish.kwargs['input']),vm_connector_settings(self.c,jwt_secret='c'*64))
        self.assertNotIn('c'*64,repr(finish.args))
        proxy=(self.d.jail_root(self.c.nextcloud_jail)/'root/cloud-installer/apache-onlyoffice.conf').read_text()
        self.assertIn('/eurooffice/',proxy)
        self.assertNotIn('/onlyoffice/',proxy)

    def test_unready_vm_or_health_failure_prevents_proxy_and_connector_finish(self):
        self.target['state']='Stopped'
        with self.assertRaises(ValueError):self.d._integrate()
        self.d.jail.assert_not_called()
        self.target['state']='Running (123)'
        self.d.jail.side_effect=RuntimeError('frontend unhealthy')
        with self.assertRaises(RuntimeError):self.d._integrate()
        self.assertEqual(self.d.jail.call_count,1)
        self.assertFalse((self.d.jail_root(self.c.nextcloud_jail)/'root/cloud-installer/apache-onlyoffice.conf').exists())


STUBS=r'''
namespace OCP {
 class Util {
  public static function needUpgrade(): bool {return $GLOBALS['p']['upgrade'] ?? false;}
  public static function getVersion(): array {return [35,0,1];}
 }
 class Server {
  public static function get(string $name): object {
   return str_contains($name,'IAppManager') ? new \EuroManager() : new \EuroConfig();
  }
 }
}
namespace {
 class EuroManager {
  public function getAppInfo(string $app): array {return ['id'=>$app,'version'=>$GLOBALS['c']['versions']['connector']];}
  public function isEnabledForAnyone(string $app): bool {return !($GLOBALS['p']['disabled'] ?? false);}
  public function isAppCompatible(string $version,array $info): bool {return true;}
 }
 class EuroConfig {
  public function setValueString(string $app,string $key,string $value,bool $lazy,bool $sensitive): void {
   if ($app!=='eurooffice' || $lazy || $value!==$GLOBALS['p']['settings']['apps']['eurooffice'][$key]) throw new \RuntimeException('Wrong app/value');
   if ($key==='jwt_secret' && !$sensitive) throw new \RuntimeException('Plaintext JWT write');
   $GLOBALS['writes'][]=['app'=>$app,'key'=>$key,'sensitive'=>$sensitive];
  }
  public function isSensitive(string $app,string $key): bool {return !($GLOBALS['p']['lost_sensitive'] ?? false);}
 }
}
'''


@unittest.skipUnless(fixtures.PHP,'PHP >=8.1 unavailable')
class EuroSensitiveImportTests(unittest.TestCase):
    def test_actual_import_routes_only_selected_app_and_marks_jwt_sensitive_first_write(self):
        runtime,_,_=payload('eurooffice')
        settings={'apps':{'eurooffice':{'DocumentServerUrl':runtime['public_url']+'eurooffice/',
            'DocumentServerInternalUrl':'http://'+runtime['onlyoffice_ip']+':8081/','StorageUrl':runtime['storage_url'],
            'jwt_secret':'c'*64,'jwt_header':'AuthorizationJWT','verify_peer_off':'false'}}}
        source=fixtures.PHP_SOURCE
        for name,replacement in (
            ('cloudInstalled','function cloudInstalled(array $c): void {}'),
            ('cloudBoot','function cloudBoot(array $c, string $command): void {}')):
            source,count=re.subn(r'(?ms)^function '+name+r'\(.*?^\}',lambda _:replacement,source)
            self.assertEqual(count,1)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'isolated.php';path.write_text(source)
            for failure in (None,'upgrade','disabled','lost_sensitive'):
                p={'runtime':runtime,'settings':settings}
                if failure:p[failure]=True
                with self.subTest(failure=failure),patch.object(fixtures,'HELPER',path):
                    result=fixtures.run_php('$writes=[]; cloudConnectorImport($c,$p["settings"]); echo json_encode($writes);',p,prelude=STUBS)
                self.assertEqual(result.returncode==0,failure is None,result.stderr)
                self.assertNotIn('c'*64,result.stdout+result.stderr)
                if failure is None:
                    writes=json.loads(result.stdout)
                    self.assertEqual(len(writes),6)
                    self.assertEqual([w for w in writes if w['key']=='jwt_secret'],[{'app':'eurooffice','key':'jwt_secret','sensitive':True}])
