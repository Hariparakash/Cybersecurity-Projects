
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, mock_open, patch


MAIN_PATH = Path(__file__).resolve().parents[1] / "main.py"


class ConfigValidationTests(unittest.TestCase):

    def valid_config(self):
        return {
            "suspicious_ports": [21, 80, 443, 65535],
            "scan_threshold": 5,
            "scan_time_window_seconds": 10
        }

    def load_main_with_open(self, open_mock):
        spec = importlib.util.spec_from_file_location(
            "main_config_test",
            MAIN_PATH
        )
        module = importlib.util.module_from_spec(spec)

        with patch("builtins.open", open_mock):
            spec.loader.exec_module(module)

        return module


    def load_main_with_config(self, config_text):
        return self.load_main_with_open(
            mock_open(read_data=config_text)
        )

    def assert_invalid_config(self, config):
        config_text = json.dumps(config)

        with self.assertRaises(SystemExit) as error:
            self.load_main_with_config(config_text)

        self.assertEqual(error.exception.code, 1)

    # Valid configuration

    def test_valid_configuration_loads(self):
        config = self.valid_config()

        module = self.load_main_with_config(json.dumps(config))

        self.assertEqual(module.suspicious_ports, config["suspicious_ports"])
        self.assertEqual(module.scan_threshold, 5)
        self.assertEqual(module.scan_time_window_seconds, 10)

    def test_valid_boundary_values_load(self):
        config = {
            "suspicious_ports": [1, 65535],
            "scan_threshold": 1,
            "scan_time_window_seconds": 0.1
        }

        module = self.load_main_with_config(json.dumps(config))

        self.assertEqual(module.suspicious_ports, [1, 65535])
        self.assertEqual(module.scan_threshold, 1)
        self.assertEqual(module.scan_time_window_seconds, 0.1)

    # File and JSON errors

    def test_missing_config_file(self):
        open_mock = Mock(side_effect=FileNotFoundError)

        with self.assertRaises(SystemExit) as error:
            self.load_main_with_open(open_mock)

        self.assertEqual(error.exception.code, 1)

    def test_invalid_json(self):
        with self.assertRaises(SystemExit) as error:
            self.load_main_with_config("{invalid json")

        self.assertEqual(error.exception.code, 1)

    def test_config_read_error(self):
        open_mock = Mock(side_effect=PermissionError)
    
        with self.assertRaises(SystemExit) as error:
            self.load_main_with_open(open_mock)
    
        self.assertEqual(error.exception.code, 1)

    # Missing required settings

    def test_missing_suspicious_ports(self):
        config = self.valid_config()
        del config["suspicious_ports"]
        self.assert_invalid_config(config)

    def test_missing_scan_threshold(self):
        config = self.valid_config()
        del config["scan_threshold"]
        self.assert_invalid_config(config)

    def test_missing_scan_time_window(self):
        config = self.valid_config()
        del config["scan_time_window_seconds"]
        self.assert_invalid_config(config)

    # Suspicious port validation

    def test_suspicious_ports_must_be_a_list(self):
        config = self.valid_config()
        config["suspicious_ports"] = "80,443"
        self.assert_invalid_config(config)

    def test_port_zero_is_rejected(self):
        config = self.valid_config()
        config["suspicious_ports"] = [0]
        self.assert_invalid_config(config)

    def test_port_above_65535_is_rejected(self):
        config = self.valid_config()
        config["suspicious_ports"] = [65536]
        self.assert_invalid_config(config)

    def test_boolean_port_is_rejected(self):
        config = self.valid_config()
        config["suspicious_ports"] = [True]
        self.assert_invalid_config(config)

    def test_float_port_is_rejected(self):
        config = self.valid_config()
        config["suspicious_ports"] = [80.5]
        self.assert_invalid_config(config)

    def test_string_port_is_rejected(self):
        config = self.valid_config()
        config["suspicious_ports"] = ["443"]
        self.assert_invalid_config(config)

    # Scan threshold validation

    def test_zero_scan_threshold_is_rejected(self):
        config = self.valid_config()
        config["scan_threshold"] = 0
        self.assert_invalid_config(config)

    def test_boolean_scan_threshold_is_rejected(self):
        config = self.valid_config()
        config["scan_threshold"] = True
        self.assert_invalid_config(config)

    def test_float_scan_threshold_is_rejected(self):
        config = self.valid_config()
        config["scan_threshold"] = 5.5
        self.assert_invalid_config(config)

    # Time window validation

    def test_zero_time_window_is_rejected(self):
        config = self.valid_config()
        config["scan_time_window_seconds"] = 0
        self.assert_invalid_config(config)

    def test_negative_time_window_is_rejected(self):
        config = self.valid_config()
        config["scan_time_window_seconds"] = -5
        self.assert_invalid_config(config)

    def test_boolean_time_window_is_rejected(self):
        config = self.valid_config()
        config["scan_time_window_seconds"] = True
        self.assert_invalid_config(config)

    def test_string_time_window_is_rejected(self):
        config = self.valid_config()
        config["scan_time_window_seconds"] = "10"
        self.assert_invalid_config(config)


if __name__ == "__main__":
    unittest.main()
