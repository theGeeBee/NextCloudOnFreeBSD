"""Actual shared PHP signed-app path with per-app native boundary stand-ins."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from nextcloud_worker_fixtures import PHP, run_php, connector_record, connector_record_text
import test_nextcloud_worker as native
from test_vm_worker_contract import payload


@unittest.skipUnless(PHP, 'PHP >=8.1 unavailable')
class VmSignedConnectorTests(unittest.TestCase):
    def php(self, expression, value, prelude=''):
        app=value['runtime']['versions']['connector_app']
        return run_php(expression,value,prelude=prelude.replace("'onlyoffice'",repr(app)))

    def settings(self,backend,directory):
        r,_,_=payload(backend)
        app=r['versions']['connector_app']
        version=r['versions']['connector']
        record=connector_record()
        record.update(version=version,phpVersionSpec='*' if backend=='eurooffice' else '>=8.3.0',
                      platformVersionSpec='>=33.0.0 <37.0.0' if backend=='eurooffice' else '>=35.0.0 <36.0.0')
        text=connector_record_text(record)
        r['versions']['connector_sha256']=hashlib.sha256(text.encode()).hexdigest()
        files=native.connector_tree(version)
        files['appinfo/info.xml']=files['appinfo/info.xml'].replace('onlyoffice',app)
        signature=json.loads(files['appinfo/signature.json'])
        signature['hashes']['appinfo/info.xml']=hashlib.sha512(files['appinfo/info.xml'].encode()).hexdigest()
        files['appinfo/signature.json']=json.dumps(signature)
        return dict(runtime=r,record_text=text,path=str(directory/app),files=files)

    def test_selected_app_signed_download_receipt_dependencies_migration_and_resume(self):
        for backend in ('eurooffice','collabora'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp)
                settings=self.settings(backend,directory)
                result=native.NextcloudPHPTests.connector_apply(self,directory,**settings)
                self.assertTrue(result['ok'],result)
                self.assertEqual(result['downloaded'][0]['id'],settings['runtime']['versions']['connector_app'])
                self.assertEqual(result['calls'],['download','verify','clear-cache','info','compatible','dependencies','receipt','install','enable'])
                again=native.NextcloudPHPTests.connector_apply(self,directory,**settings,installed=settings['runtime']['versions']['connector'])
                self.assertTrue(again['ok'],again)
                self.assertNotIn('download',again['calls'])
                self.assertNotIn('install',again['calls'])

    def test_partial_copy_changed_signature_and_failed_dependencies_do_not_migrate(self):
        for backend in ('eurooffice','collabora'):
            for failure in ('partial','signature','dependency','wrong-app'):
                with self.subTest(backend=backend,failure=failure),tempfile.TemporaryDirectory() as tmp:
                    directory=Path(tmp); settings=self.settings(backend,directory)
                    if failure=='partial':
                        Path(settings['path']).mkdir()
                    elif failure=='signature':
                        settings['files']['lib/Application.php']+=' changed'
                    elif failure=='dependency': settings['dependency_error']=True
                    else:
                        # Even a completely signed tree cannot substitute a
                        # different connector namespace for the selected app.
                        settings['files']['appinfo/info.xml']=settings['files']['appinfo/info.xml'].replace(
                            '<id>'+settings['runtime']['versions']['connector_app']+'</id>','<id>onlyoffice</id>')
                        signature=json.loads(settings['files']['appinfo/signature.json'])
                        signature['hashes']['appinfo/info.xml']=hashlib.sha512(settings['files']['appinfo/info.xml'].encode()).hexdigest()
                        settings['files']['appinfo/signature.json']=json.dumps(signature)
                    result=native.NextcloudPHPTests.connector_apply(self,directory,**settings)
                    self.assertFalse(result['ok'],result)
                    self.assertNotIn('install',result['calls'])
                    self.assertNotIn('enable',result['calls'])
                    self.assertNotIn('mutable-latest',result['calls'])

    def test_manifest_php_forms_remain_backend_scoped_and_none_has_no_connector(self):
        for backend in ('eurooffice','collabora'):
            with tempfile.TemporaryDirectory() as tmp:
                settings=self.settings(backend,Path(tmp))
                c=settings['runtime']
                app=c['versions']['connector_app']
                for other in ('onlyoffice','richdocumentscode'):
                    result=run_php("cloudConnectorVersion($c,$p['info']);",{'runtime':c,'info':{'id':other,'version':c['versions']['connector']}})
                    self.assertNotEqual(result.returncode,0)
                result=run_php("echo cloudConnectorId($c);",{'runtime':c})
                self.assertEqual(result.stdout,app)
