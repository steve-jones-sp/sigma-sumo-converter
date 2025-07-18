#!/usr/bin/env python3
"""
Unit tests for the Sigma to Sumo Logic CSE Converter
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add the parent directory to the path to import the main module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sigma_sumo_converter import (
    ConversionResult,
    DetectionLogicTranslator,
    FieldMapper,
    LogSourceMapper,
    MetadataMapper,
    SigmaToSumoConverter,
)


class TestFieldMapper(unittest.TestCase):
    """Test the FieldMapper class"""

    def setUp(self):
        self.field_mapper = FieldMapper()

    def test_basic_field_mapping(self):
        """Test basic field mapping functionality"""
        # Test Windows process creation mapping
        logsource = {"product": "windows", "category": "process_creation"}

        mapped_field = self.field_mapper.map_field("Image", logsource)
        self.assertEqual(mapped_field, "baseImage")

        mapped_field = self.field_mapper.map_field("CommandLine", logsource)
        self.assertEqual(mapped_field, "commandLine")

    def test_unknown_field_passthrough(self):
        """Test that unknown fields pass through unchanged"""
        logsource = {"product": "windows", "category": "process_creation"}

        mapped_field = self.field_mapper.map_field("UnknownField", logsource)
        self.assertEqual(mapped_field, "UnknownField")

    def test_cloud_mapping(self):
        """Test cloud service field mapping"""
        logsource = {"product": "aws", "service": "cloudtrail"}

        mapped_field = self.field_mapper.map_field("eventName", logsource)
        self.assertEqual(mapped_field, "action")

        mapped_field = self.field_mapper.map_field("sourceIPAddress", logsource)
        self.assertEqual(mapped_field, "srcDevice_ip")


class TestDetectionLogicTranslator(unittest.TestCase):
    """Test the DetectionLogicTranslator class"""

    def setUp(self):
        self.field_mapper = FieldMapper()
        self.translator = DetectionLogicTranslator(self.field_mapper)

    def test_basic_condition_translation(self):
        """Test basic condition translation"""
        condition = self.translator.translate_condition(
            "Image", "endswith", "powershell.exe"
        )
        expected = 'Image like ("%powershell.exe")'
        self.assertEqual(condition, expected)

    def test_contains_condition(self):
        """Test contains condition translation"""
        condition = self.translator.translate_condition(
            "CommandLine", "contains", "Invoke-Expression"
        )
        expected = 'CommandLine like ("%Invoke-Expression%")'
        self.assertEqual(condition, expected)

    def test_multiple_values_condition(self):
        """Test condition with multiple values"""
        values = ["powershell.exe", "cmd.exe", "bash"]
        condition = self.translator.translate_condition("Image", "endswith", values)
        expected = 'Image like ("%powershell.exe" OR "%cmd.exe" OR "%bash")'
        self.assertEqual(condition, expected)

    def test_field_mapping_in_translation(self):
        """Test that field mapping is applied during translation"""
        logsource = {"product": "windows", "category": "process_creation"}
        self.translator.set_logsource(logsource)

        condition = self.translator.translate_condition(
            "Image", "endswith", "powershell.exe"
        )
        expected = 'baseImage like ("%powershell.exe")'
        self.assertEqual(condition, expected)


class TestMetadataMapper(unittest.TestCase):
    """Test the MetadataMapper class"""

    def test_mitre_attack_mapping(self):
        """Test MITRE ATT&CK tag mapping"""
        sigma_tags = ["attack.execution", "attack.t1059.001", "sysmon"]
        mapped_tags = MetadataMapper.map_tags(sigma_tags)

        self.assertIn("_mitreAttackTactic:TA0002", mapped_tags)
        self.assertIn("_mitreAttackTechnique:T1059.001", mapped_tags)

    def test_category_determination(self):
        """Test category determination from tags"""
        sigma_tags = ["attack.execution", "attack.t1059.001"]
        category = MetadataMapper.get_category(sigma_tags)
        self.assertEqual(category, "Execution")

    def test_severity_mapping(self):
        """Test severity level mapping"""
        self.assertEqual(MetadataMapper.get_severity_score("low"), 2)
        self.assertEqual(MetadataMapper.get_severity_score("medium"), 4)
        self.assertEqual(MetadataMapper.get_severity_score("high"), 6)
        self.assertEqual(MetadataMapper.get_severity_score("critical"), 8)

    def test_tag_filtering(self):
        """Test that tag filtering works properly"""
        # Test with many tags to verify filtering
        many_tags = [
            "attack.execution",
            "attack.t1059.001",
            "attack.t1059.002",
            "attack.t1059.003",
            "attack.t1059.004",
            "attack.t1059.005",
            "attack.persistence",
            "attack.defense-evasion",
            "cve.2021-1234",
            "cve.2022-5678",
            "cve.2023-9012",
            "sysmon",
            "detection.emerging_threats",
        ]

        mapped_tags = MetadataMapper.map_tags(many_tags)

        # Should have reasonable number of tags
        self.assertLessEqual(len(mapped_tags), 12)

        # Should prioritize important tags
        self.assertTrue(any("_mitreAttackTactic:" in tag for tag in mapped_tags))
        self.assertTrue(any("_mitreAttackTechnique:" in tag for tag in mapped_tags))


class TestSigmaToSumoConverter(unittest.TestCase):
    """Test the main converter class"""

    def setUp(self):
        self.converter = SigmaToSumoConverter()

    def test_basic_conversion(self):
        """Test basic Sigma rule conversion"""
        sigma_yaml = """
title: Test PowerShell Rule
id: 12345678-1234-1234-1234-123456789012
description: Test rule for PowerShell detection
author: Test Author
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: powershell.exe
        CommandLine|contains: Invoke-Expression
    condition: selection
"""
        result = self.converter.convert_sigma_rule(sigma_yaml)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.api_json)

        # Check basic structure
        fields = result.api_json["fields"]
        self.assertEqual(fields["name"], "Test PowerShell Rule")
        self.assertEqual(fields["category"], "Execution")
        self.assertEqual(fields["scoreMapping"]["default"], 6)  # high = 6

        # Check that expression contains expected elements
        expression = fields["expression"]
        self.assertIn('metadata_vendor="Microsoft"', expression)
        self.assertIn("baseImage like", expression)
        self.assertIn("commandLine like", expression)

    def test_missing_required_fields(self):
        """Test handling of missing required fields"""
        sigma_yaml = """
description: Rule without title
detection:
    selection:
        Image: test.exe
    condition: selection
"""
        result = self.converter.convert_sigma_rule(sigma_yaml)

        self.assertFalse(result.success)
        self.assertIn("Missing required field: title", result.errors)

    def test_aws_cloudtrail_conversion(self):
        """Test AWS CloudTrail rule conversion"""
        sigma_yaml = """
title: AWS Root User Activity
id: 12345678-1234-1234-1234-123456789012
description: Detects AWS root user activity
author: Security Team
level: medium
tags:
    - attack.persistence
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: ConsoleLogin
        userIdentity.type: Root
    condition: selection
"""
        result = self.converter.convert_sigma_rule(sigma_yaml)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.api_json)

        fields = result.api_json["fields"]
        self.assertEqual(fields["name"], "AWS Root User Activity")
        self.assertEqual(fields["category"], "Persistence")

        expression = fields["expression"]
        self.assertIn('metadata_vendor="Amazon AWS"', expression)
        self.assertIn("action=", expression)

    def test_file_conversion(self):
        """Test file-based conversion"""
        sigma_content = """
title: Test File Conversion
id: 12345678-1234-1234-1234-123456789012
description: Test file conversion functionality
level: medium
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: test.exe
    condition: selection
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(sigma_content)
            temp_file = f.name

        try:
            # Create temporary output directory
            with tempfile.TemporaryDirectory() as temp_dir:
                success = self.converter.convert_file(temp_file, temp_dir)
                self.assertTrue(success)

                # Check that output file was created
                output_files = list(Path(temp_dir).rglob("*.json"))
                self.assertGreater(len(output_files), 0)

                # Check output file content
                with open(output_files[0], "r") as f:
                    output_data = json.load(f)
                    self.assertEqual(
                        output_data["fields"]["name"], "Test File Conversion"
                    )

        finally:
            os.unlink(temp_file)


class TestIntegration(unittest.TestCase):
    """Integration tests with real-world examples"""

    def setUp(self):
        self.converter = SigmaToSumoConverter()

    def test_complex_sigma_rule(self):
        """Test conversion of a complex Sigma rule with multiple conditions"""
        sigma_yaml = """
title: Suspicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects suspicious PowerShell command line patterns that may indicate malicious activity
author: Security Team
date: 2024/01/15
modified: 2024/07/17
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1027
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
            - 'Invoke-WebRequest'
            - 'curl'
            - 'wget'
            - 'DownloadString'
            - 'DownloadFile'
    selection_encoded:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -e '
    condition: selection_img and (selection_cli or selection_encoded)
falsepositives:
    - Legitimate PowerShell scripts
    - System administration activities
"""

        result = self.converter.convert_sigma_rule(sigma_yaml)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.api_json)

        fields = result.api_json["fields"]

        # Verify basic metadata
        self.assertEqual(fields["name"], "Suspicious PowerShell Execution")
        self.assertEqual(fields["category"], "Execution")
        self.assertEqual(fields["scoreMapping"]["default"], 6)

        # Verify tags include MITRE ATT&CK
        tags = fields["tags"]
        self.assertTrue(
            any("_mitreAttackTactic:TA0002" in tag for tag in tags)
        )  # Execution
        self.assertTrue(
            any("_mitreAttackTechnique:T1059.001" in tag for tag in tags)
        )  # PowerShell

        # Verify expression structure
        expression = fields["expression"]
        self.assertIn('metadata_vendor="Microsoft"', expression)
        self.assertIn("baseImage like", expression)
        self.assertIn("commandLine like", expression)

    def test_linux_auditd_rule(self):
        """Test conversion of a Linux auditd rule"""
        sigma_yaml = """
title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789012
description: Detects suspicious process execution on Linux systems
author: Security Team
level: medium
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
        a0|endswith:
            - '/bin/sh'
            - '/bin/bash'
        a1|contains:
            - 'curl'
            - 'wget'
            - 'nc'
    condition: selection
"""

        result = self.converter.convert_sigma_rule(sigma_yaml)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.api_json)

        fields = result.api_json["fields"]
        self.assertEqual(fields["name"], "Suspicious Process Execution")
        self.assertEqual(fields["category"], "Execution")


if __name__ == "__main__":
    # Create a test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFieldMapper))
    suite.addTests(loader.loadTestsFromTestCase(TestDetectionLogicTranslator))
    suite.addTests(loader.loadTestsFromTestCase(TestMetadataMapper))
    suite.addTests(loader.loadTestsFromTestCase(TestSigmaToSumoConverter))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with proper code
    exit(0 if result.wasSuccessful() else 1)
