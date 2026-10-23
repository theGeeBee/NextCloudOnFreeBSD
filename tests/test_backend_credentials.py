"""Exact create/save/load credential schemas; values are never printed."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock

from installer.main import load_secrets
from installer.wizard import create_secrets
from installer.state import atomic_json


class BackendCredentialTests(unittest.TestCase):
    def test_generated_credentials_roundtrip_for_each_immutable_backend(self):
        with tempfile.TemporaryDirectory() as temp:
            for backend in ('onlyoffice','eurooffice','collabora','none'):
                with self.subTest(backend=backend):
                    ui=Mock();value=create_secrets(ui=ui,generate=True,backend=backend)
                    expected={'admin_password','db_password'}|({'jwt_secret'} if backend in ('onlyoffice','eurooffice') else set())
                    self.assertEqual(set(value),expected)
                    path=Path(temp)/(backend+'.json');atomic_json(path,value)
                    self.assertEqual(load_secrets(path,backend=backend),value)
                    self.assertNotIn(value['admin_password'],repr(ui.mock_calls))

    def test_code_and_none_refuse_jwt_or_extra_credentials_not_ignore_them(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'private.json'
            for backend in ('collabora','none'):
                value=create_secrets(ui=Mock(),generate=True,backend=backend)
                atomic_json(path,{**value,'jwt_secret':'a'*64})
                with self.assertRaisesRegex(ValueError,'schema'):load_secrets(path,backend=backend)
