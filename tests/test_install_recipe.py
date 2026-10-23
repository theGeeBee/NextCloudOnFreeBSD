"""Public recipe defaults; pure validation, no host probes or provisioning."""

import json
from pathlib import Path
import unittest

from installer.config import Config, DEFAULT_NEXTCLOUD_APPS, DEFAULT_ONLYOFFICE_PLUGINS, QUOTA_FIELDS


class InstallRecipeTests(unittest.TestCase):
    def test_example_explicitly_preserves_new_install_selections(self):
        value = json.loads((Path(__file__).resolve().parents[1] / "examples/config.json").read_text())
        config = Config.from_json(json.dumps(value)).validate_provisioning()
        self.assertEqual(value["storage_policy"], "optional")
        for name in QUOTA_FIELDS:
            self.assertEqual(value[name], 0)
        self.assertEqual(config.onlyoffice_plugins, DEFAULT_ONLYOFFICE_PLUGINS)
        self.assertEqual(len(config.selected_onlyoffice_plugins), 9)
        self.assertNotIn("wordpress", config.selected_onlyoffice_plugins)
        self.assertEqual(config.nextcloud_apps, DEFAULT_NEXTCLOUD_APPS)
        self.assertEqual(config.font_profile, "comprehensive")
        self.assertEqual(config.additional_fonts_dir, "")
        self.assertNotIn("password", value)
        self.assertNotIn("secrets", value)
        self.assertFalse(config.accept_microsoft_fonts)


if __name__ == "__main__":
    unittest.main()
