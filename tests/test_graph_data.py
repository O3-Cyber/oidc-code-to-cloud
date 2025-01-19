import unittest
from unittest.mock import MagicMock, patch
from modules.graph_data import get_graph_data, get_federated_credentials

class TestGraphData(unittest.TestCase):
    @patch('modules.graph_data.requests.get')
    def test_get_graph_data(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "value": [{"id": "1"}, {"id": "2"}],
            "@odata.nextLink": None
        }
        mock_get.return_value = mock_response

        auth_client = MagicMock()
        auth_client.get_token.return_value = "fake_token"

        data = get_graph_data(auth_client, "fake_endpoint")
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["id"], "1")
        self.assertEqual(data[1]["id"], "2")

    @patch('modules.graph_data.get_graph_data')
    def test_get_federated_credentials(self, mock_get_graph_data):
        mock_get_graph_data.return_value = [{"name": "cred1"}, {"name": "cred2"}]

        auth_client = MagicMock()
        app_id = "fake_app_id"

        creds = get_federated_credentials(auth_client, app_id)
        self.assertEqual(len(creds), 2)
        self.assertEqual(creds[0]["name"], "cred1")
        self.assertEqual(creds[1]["name"], "cred2")

if __name__ == '__main__':
    unittest.main()
