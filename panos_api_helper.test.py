import json
import unittest
import warnings
from os.path import expanduser, join

API_KEY_FILE = join(expanduser("~"), ".panos", "api_key.json")  # {"ApiKey": "todo"}
with open(API_KEY_FILE, "r") as f:
    config_data = json.load(f)


func = __import__("panos_api_helper")


def get_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ret = s.getsockname()[0]
    s.close()
    return ret


class TestFunction(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        warnings.filterwarnings("ignore", category=ResourceWarning, message="unclosed.*<ssl.SSLSocket.*>")

    def test_find_fw_rule(self):
        MY_FW_GROUP = "northsouth"
        src_ip = "11.22.255.111"
        dst_ip = "11.22.255.222"
        dst_port = 443

        fw_url = func.find_fw_url(MY_FW_GROUP)
        result = func.PanosXmlApiClient.security_policy_match(fw_url, src_ip, dst_ip, 6, dst_port)
        print(json.dumps(result, indent=2))

        self.assertRegex(result["@name"], "northso", "Should match")
        self.assertIn(result["action"], ["allow", "deny"])

        if result["action"] == "allow":
            self.assertGreater(len(result["source"]["member"]), 0)
            self.assertGreater(len(result["application_service"]["member"]), 0)

    def test_find_fw_rule_invalid_arguments(self):
        MY_FW_GROUP = "northsouth"
        src_ip = "11.22.255.111"
        dst_ip = "11.22.255.222"
        dst_port = "dummy"

        fw_url = func.find_fw_url(MY_FW_GROUP)
        result = func.PanosXmlApiClient.security_policy_match(fw_url, src_ip, dst_ip, 6, dst_port)
        print(json.dumps(result, indent=2))

        self.assertEqual(
            result["line"],
            [
                "test -> security-policy-match -> destination-port 'dummy' is not a valid integer",
                "test -> security-policy-match -> destination-port is invalid"
            ],
        )

    def test_find_user_by_ip(self):
        MY_IP = get_ip()
        MY_FW_GROUP = "edge"

        result = func.find_user_by_ip(MY_IP, MY_FW_GROUP)

        self.assertTrue(result["username"])
        self.assertTrue(result["primary-username"])
        self.assertTrue(result["computer"])
        self.assertTrue(result["virtual-ip"] == MY_IP or result["public-ip"] == MY_IP or result["client-ip"] == MY_IP)
        self.assertTrue(result["firewall-url"])


if __name__ == "__main__":
    unittest.main()
