import unittest
from unittest.mock import MagicMock, patch
import cpa_oauth

class CPAOAuthModuleTests(unittest.TestCase):
    def test_start_cpa_xai_auth_validates_config(self):
        with self.assertRaises(ValueError):
            cpa_oauth.start_cpa_xai_auth("", "secret")
        with self.assertRaises(ValueError):
            cpa_oauth.start_cpa_xai_auth("http://localhost:8317", "")

    @patch("cpa_oauth.requests.get")
    def test_start_cpa_xai_auth_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "ok",
            "url": "https://accounts.x.ai/oauth2/device?user_code=ABCD-1234",
            "state": "xai-123",
            "user_code": "ABCD-1234"
        }
        mock_get.return_value = mock_resp

        res = cpa_oauth.start_cpa_xai_auth("http://localhost:8317", "key")
        self.assertEqual(res["user_code"], "ABCD-1234")
        self.assertEqual(res["state"], "xai-123")

    @patch("cpa_oauth.requests.get")
    def test_poll_cpa_auth_status_ok(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        mock_get.return_value = mock_resp

        ok = cpa_oauth.poll_cpa_auth_status("http://localhost:8317", "key", "xai-123", timeout=2, interval=0.1)
        self.assertTrue(ok)

if __name__ == "__main__":
    unittest.main()
