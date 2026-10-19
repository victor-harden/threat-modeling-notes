import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import threat_model


class ThreatModelTests(unittest.TestCase):
    def test_parse_component(self):
        comps = threat_model.parse_components(["Web app:web"])
        self.assertEqual(comps, [{"name": "Web app", "type": "web"}])

    def test_invalid_component(self):
        with self.assertRaises(ValueError):
            threat_model.parse_components(["NoType"])

    def test_unknown_type(self):
        with self.assertRaises(ValueError):
            threat_model.parse_components(["Thing:spaceship"])

    def test_web_component_threats(self):
        model = threat_model.build([{"name": "Web", "type": "web"}])
        categories = {t["category"] for t in model[0]["threats"]}
        self.assertIn("information-disclosure", categories)
        self.assertEqual(len(categories), 4)

    def test_risk_computed(self):
        model = threat_model.build([{"name": "API", "type": "api"}], 4, 5)
        self.assertTrue(all(t["risk"] == 20 for t in model[0]["threats"]))

    def test_render_markdown(self):
        model = threat_model.build(threat_model.parse_components(["DB:db"]))
        text = threat_model.render(model)
        self.assertIn("## DB (db)", text)
        self.assertIn("| STRIDE |", text)

    def test_cli_json_and_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "model.json"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = threat_model.main(["--component", "API:api", "--json", "--out", str(out)])
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text())
            self.assertEqual(payload[0]["type"], "api")


if __name__ == "__main__":
    unittest.main()
