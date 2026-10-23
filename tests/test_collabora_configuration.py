"""CODE selected-XML seam on representative fixtures, not live WOPI acceptance."""
from dataclasses import replace
import hashlib
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

from installer.config import Config
from installer.office_vm import collabora_configuration


XML='''<config>
<server_name />
<net><service_root /><proto>all</proto><post_allow allow="true"><host>10.0.0.0/8</host></post_allow>
<lok_allow><host>.*</host></lok_allow></net>
<ssl><enable>true</enable><termination>false</termination><ssl_verification>false</ssl_verification></ssl>
<storage><wopi allow="true"><alias_groups mode="first"><!-- sample only --></alias_groups></wopi>
<ssl><as_scheme>true</as_scheme><ca_file_path /></ssl></storage>
<admin_console><enable>true</enable><password /></admin_console>
<security><capabilities>true</capabilities><seccomp>true</seccomp></security>
<unrelated retained="yes">vendor-default</unrelated>
</config>'''


class CollaboraConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.digest=hashlib.sha256(XML.encode()).hexdigest()

    def render(self,c=None,text=XML,digest=None):
        return ET.fromstring(collabora_configuration(text,c or self.c,expected_sha256=digest or self.digest))

    def test_exact_wopi_group_private_callback_and_strict_tls_without_capability_relaxation(self):
        root=self.render(replace(self.c,public_https_port=9443))
        self.assertEqual(root.findtext('server_name'),self.c.public_hostname+':9443')
        self.assertEqual(root.findtext('net/service_root'),'/collabora')
        self.assertEqual(root.findtext('net/proto'),'IPv4')
        self.assertEqual(root.findtext('ssl/enable'),'false')
        self.assertEqual(root.findtext('ssl/termination'),'true')
        self.assertEqual(root.findtext('ssl/ssl_verification'),'true')
        self.assertEqual(root.findtext('storage/ssl/as_scheme'),'true')
        self.assertEqual(root.findtext('admin_console/enable'),'false')
        self.assertEqual(root.findtext('security/capabilities'),'true')
        self.assertEqual(root.findtext('security/seccomp'),'true')
        groups=root.find('storage/wopi/alias_groups')
        self.assertEqual(groups.attrib['mode'],'groups')
        self.assertEqual(len(groups),1)
        host=groups.findtext('group/host')
        self.assertEqual(host,'https://'+re.escape(self.c.public_hostname)+':443')
        self.assertFalse(re.fullmatch(host,'https://'+self.c.public_hostname.replace('.','x')+':443'))
        self.assertTrue(re.fullmatch(host,'https://'+self.c.public_hostname+':443'))
        for path in ('net/post_allow','net/lok_allow'):
            self.assertEqual([child.text for child in root.find(path)],[self.c.nextcloud_ip+'/32'])
        self.assertEqual(root.findtext('unrelated'),'vendor-default')

    def test_external_callback_is_http_private_not_falsely_claimed_tls(self):
        c=replace(self.c,tls_mode='external',proxy_networks='192.0.2.9/32',http_port=8080)
        root=self.render(c)
        self.assertEqual(root.findtext('storage/wopi/alias_groups/group/host'),'http://'+re.escape(c.nextcloud_ip)+':80')
        self.assertEqual(root.findtext('ssl/ssl_verification'),'true')

    def test_public_ca_path_only_no_host_private_paths_or_passwords(self):
        c=replace(self.c,ca_file='/root/public-ca.pem')
        root=self.render(c)
        self.assertEqual(root.findtext('storage/ssl/ca_file_path'),'/etc/coolwsd/nextcloud-ca.pem')
        self.assertNotIn(c.ca_file,ET.tostring(root,encoding='unicode'))

    def test_changed_source_wrong_backend_and_ambiguous_layout_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'hash-verified'):
            self.render(text=XML+' ')
        c=replace(self.c,office_backend='eurooffice')
        with self.assertRaises(ValueError): self.render(c)
        for text in (XML.replace('<proto>all</proto>',''),XML.replace('<proto>all</proto>','<proto>all</proto><proto>IPv6</proto>')):
            with self.assertRaisesRegex(ValueError,'layout changed'):
                self.render(text=text,digest=hashlib.sha256(text.encode()).hexdigest())
