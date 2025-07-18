#!/usr/bin/env python3
"""
Sigma to Sumo Logic CSE Rule Converter v1.0.0

This tool converts Sigma detection rules (YAML format) to Sumo Logic CSE rules.
It handles field mapping to normalized schema, detection logic translation,
and metadata conversion using separate JSON mapping files.
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import yaml

    HAS_YAML = True
    print("✅ PyYAML imported successfully")
except ImportError:
    HAS_YAML = False
    print("⚠️  PyYAML not available - using fallback parser")

print("🔧 Script starting...")
print("✅ All imports successful")


@dataclass
class ConversionResult:
    """Result of a conversion operation"""

    success: bool
    rule_json: Optional[Dict[str, Any]] = None
    api_json: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None  # Change from List[str] = None
    warnings: Optional[List[str]] = None  # Change from List[str] = None


class FieldMapper:
    """Maps Sigma fields to Sumo Logic CSE normalized schema fields using JSON mapping files"""

    def __init__(self):
        self.mappings_cache = {}
        self.mappings_dir = Path(__file__).parent / "field_mappings"
        self.ensure_mappings_directory()

    def ensure_mappings_directory(self):
        """Create mappings directory structure if it doesn't exist"""
        self.mappings_dir.mkdir(exist_ok=True)

        # Create product-specific directories
        product_dirs = [
            "windows",
            "linux",
            "macos",
            "generic",
            "application",
            "cloud",
            "network",
            "product",
            "category",
        ]

        for product_dir in product_dirs:
            (self.mappings_dir / product_dir).mkdir(exist_ok=True)
            print(f"📁 Ensured directory exists: field_mappings/{product_dir}")

    def get_mapping_for_logsource(self, logsource: Dict[str, str]) -> Dict[str, Any]:
        """Get the appropriate field mapping based on log source"""
        product = logsource.get("product", "").lower()
        category = logsource.get("category", "").lower()
        service = logsource.get("service", "").lower()

        # Determine mapping file based on log source hierarchy
        mapping_file = None

        # Product-specific mappings - Updated to match your actual file names
        if product == "windows":
            if category == "process_creation":
                mapping_file = "windows/windows_process_creation.json"
            elif category == "network_connection":
                mapping_file = "windows/windows_network_connection.json"
            elif category == "file_event":
                mapping_file = "windows/windows_file_event.json"
            elif category == "registry_event":
                mapping_file = "windows/windows_registry_event.json"
            elif category == "image_load":
                mapping_file = "windows/windows_image_load.json"
            elif category == "dns_query":
                mapping_file = "windows/windows_dns_query.json"
            elif category == "wmi_event":
                mapping_file = "windows/windows_wmi_event.json"
            elif service == "powershell":
                mapping_file = "windows/windows_powershell.json"
            elif service == "security":
                mapping_file = "windows/windows_security.json"
            else:
                # Default Windows mapping - try the first available
                mapping_file = "windows/windows_process_creation.json"

        elif product == "linux":
            if category == "process_creation":
                mapping_file = "linux/linux_process_creation.json"
            elif service == "auditd":
                mapping_file = "linux/linux_auditd.json"
            else:
                # Default Linux mapping
                mapping_file = "linux/linux_process_creation.json"

        elif product in ["aws", "azure", "gcp", "m365", "okta", "github"]:
            if product == "aws":
                if service == "cloudtrail":
                    mapping_file = "cloud/aws_cloudtrail.json"
                else:
                    mapping_file = "cloud/aws_cloudtrail.json"  # Default AWS
            elif product == "azure":
                if service == "signinlogs":
                    mapping_file = "cloud/azure_signinlogs.json"
                else:
                    mapping_file = "cloud/azure_signinlogs.json"  # Default Azure
            else:
                mapping_file = f"cloud/{product}.json"

        # Category-only mappings - Updated to match your actual file names
        elif category in ["firewall", "proxy", "dns"]:
            mapping_file = f"network/category_{category}.json"
        elif category in ["webserver", "antivirus"]:
            mapping_file = f"category/{category}.json"

        # Fallback to generic
        if not mapping_file:
            mapping_file = "generic/generic.json"

        # Load the mapping file
        mapping_data = self.load_mapping_file(mapping_file)
        if not mapping_data:
            print(f"⚠️  Using generic mapping for {product}/{category}/{service}")
            mapping_data = self.load_mapping_file("generic/generic.json")

        return mapping_data

    def load_mapping_file(self, relative_path: str) -> Dict[str, Any]:
        """Load a field mapping file by relative path"""
        if relative_path in self.mappings_cache:
            return self.mappings_cache[relative_path]

        mapping_file = self.mappings_dir / relative_path
        if not mapping_file.exists():
            print(f"⚠️  Mapping file not found: {relative_path}")
            return {}

        try:
            with open(mapping_file, "r", encoding="utf-8") as f:
                mapping_data = json.load(f)
                self.mappings_cache[relative_path] = mapping_data
                return mapping_data
        except Exception as e:
            print(f"❌ Error loading mapping file {relative_path}: {str(e)}")
            return {}

    def map_field(
        self, sigma_field: str, logsource: Optional[Dict[str, str]] = None
    ) -> str:
        """Map a Sigma field to Sumo Logic CSE normalized field"""
        if logsource:
            mapping_data = self.get_mapping_for_logsource(logsource)
            field_mappings = mapping_data.get("field_mappings", {})
            return field_mappings.get(sigma_field, sigma_field)

        # Fallback to original behavior if no logsource provided
        return sigma_field


class DetectionLogicTranslator:
    """Translates Sigma detection logic to Sumo Logic CSE query syntax"""

    def __init__(self, field_mapper: FieldMapper):
        self.field_mapper = field_mapper
        self.current_logsource = None

    def set_logsource(self, logsource: Dict[str, str]) -> None:
        """Set the current log source for field mapping"""
        self.current_logsource = logsource

    def translate_condition(
        self, field: str, operator: str, values: Union[str, List[str]]
    ) -> str:
        """Translate a single condition to Sumo Logic CSE syntax"""
        sumo_field = self.field_mapper.map_field(field, self.current_logsource)

        if isinstance(values, str):
            values = [values]

        # Clean up values and remove empty/whitespace-only entries
        cleaned_values = [self._escape_value(val) for val in values if val.strip()]

        if not cleaned_values:
            return ""

        if operator == "endswith":
            value_conditions = [f'"%{val}"' for val in cleaned_values]
        elif operator == "startswith":
            value_conditions = [f'"{val}%"' for val in cleaned_values]
        elif operator == "contains":
            value_conditions = [f'"%{val}%"' for val in cleaned_values]
        elif operator == "equals" or operator == "":
            if len(cleaned_values) == 1:
                return f'{sumo_field}="{cleaned_values[0]}"'
            else:
                value_conditions = [f'"{val}"' for val in cleaned_values]
                return f'{sumo_field} IN ({", ".join(value_conditions)})'
        else:
            # Default to contains for unknown operators
            value_conditions = [f'"%{val}%"' for val in cleaned_values]

        # Format with proper line breaks for readability (3 values per line)
        if len(value_conditions) <= 3:
            # Short lists stay on one line
            condition_str = " OR ".join(value_conditions)
        else:
            # Long lists get formatted with 3 values per line
            formatted_lines = []
            for i in range(0, len(value_conditions), 3):
                line_values = value_conditions[i : i + 3]
                if i == 0:
                    # First line doesn't need OR prefix
                    formatted_lines.append(" OR ".join(line_values))
                else:
                    # Subsequent lines start with OR
                    formatted_lines.append("OR " + " OR ".join(line_values))
            condition_str = "\n    ".join(formatted_lines)

        return f"{sumo_field} like ({condition_str})"

    def _escape_value(self, value: str) -> str:
        """Escape special characters in values"""
        # Escape quotes first
        value = value.replace('"', '\\"')

        # Handle Unicode escape sequences safely
        try:
            # Only attempt unicode_escape if it looks like it might contain actual escape sequences
            if "\\u" in value or "\\x" in value or "\\n" in value or "\\t" in value:
                value = value.encode("utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            # If decoding fails, just use the original value
            pass

        return value

    def translate_detection(self, detection: Dict[str, Any]) -> str:
        """Translate full detection block to Sumo Logic CSE expression"""
        selections = []

        for key, value in detection.items():
            if key == "condition":
                continue

            if isinstance(value, dict):
                field_conditions = []
                for field, criteria in value.items():
                    field_name, operator = self._parse_field_operator(field)
                    condition = self.translate_condition(field_name, operator, criteria)
                    if condition:  # Only add non-empty conditions
                        field_conditions.append(condition)

                if field_conditions:
                    # Join field conditions with AND and newlines for readability
                    formatted_conditions = "\nAND ".join(field_conditions)
                    selections.append(f"({formatted_conditions})")

        # Join selections with AND and newlines
        return "\nAND ".join(selections) if selections else ""

    def _parse_field_operator(self, field_spec: str) -> Tuple[str, str]:  # type: ignore
        """Parse field specification like 'Image|endswith' into field and operator"""
        if "|" in field_spec:
            field, operator = field_spec.split("|", 1)
            return field.strip(), operator.strip()
        return field_spec.strip(), "equals"


class MetadataMapper:
    """Maps Sigma metadata to Sumo Logic CSE format"""

    MITRE_TACTIC_MAPPINGS = {
        "attack.initial-access": "TA0001",
        "attack.execution": "TA0002",
        "attack.persistence": "TA0003",
        "attack.privilege-escalation": "TA0004",
        "attack.defense-evasion": "TA0005",
        "attack.credential-access": "TA0006",
        "attack.discovery": "TA0007",
        "attack.lateral-movement": "TA0008",
        "attack.collection": "TA0009",
        "attack.exfiltration": "TA0010",
        "attack.command-and-control": "TA0011",
        "attack.impact": "TA0012",
    }

    CATEGORY_MAPPINGS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0012": "Impact",
    }

    SEVERITY_MAPPINGS = {"low": 2, "medium": 4, "high": 6, "critical": 8}

    @classmethod
    def map_tags(cls, sigma_tags: List[str]) -> List[str]:
        """Convert Sigma tags to Sumo Logic CSE format with intelligent filtering"""
        mitre_tactics = []
        mitre_techniques = []
        cve_tags = []
        other_important_tags = []

        # Categorize tags
        for tag in sigma_tags:
            if tag.startswith("attack."):
                # Map MITRE ATT&CK tactics
                if tag in cls.MITRE_TACTIC_MAPPINGS:
                    mitre_tactics.append(
                        f"_mitreAttackTactic:{cls.MITRE_TACTIC_MAPPINGS[tag]}"
                    )
                # Handle technique tags like attack.t1003.003
                elif tag.startswith("attack.t"):
                    technique = tag.replace("attack.t", "T").upper()
                    mitre_techniques.append(f"_mitreAttackTechnique:{technique}")
            elif tag.startswith("cve.") or tag.startswith("CVE-"):
                # Keep CVE tags - convert to proper format
                if tag.startswith("cve."):
                    cve_id = tag.replace("cve.", "CVE-").upper()
                else:
                    cve_id = tag.upper()
                cve_tags.append(f"_cve:{cve_id}")
            elif tag.lower() in [
                "detection.emerging_threats",
                "detection.threat_hunting",
                "sysmon",
            ]:
                # Keep some important detection-related tags
                other_important_tags.append(tag)
            elif tag in cls.CATEGORY_MAPPINGS.values():
                # Handle tactic names that appear as plain text (e.g., "Credential Access")
                # Convert back to attack.* format for processing
                for attack_tag, tactic_id in cls.MITRE_TACTIC_MAPPINGS.items():
                    if cls.CATEGORY_MAPPINGS.get(tactic_id) == tag:
                        mitre_tactics.append(f"_mitreAttackTactic:{tactic_id}")
                        break
            # Skip threat actor names, tool names, technique descriptions, etc.

        # Apply threshold logic to prevent tag overload
        MAX_TACTICS = 3
        MAX_TECHNIQUES = 5
        MAX_CVES = 2
        MAX_TOTAL_TAGS = 12  # Reasonable limit for Sumo Logic CSE

        final_tags = []

        # Add tactics (limit to 3 - most important ones)
        final_tags.extend(mitre_tactics[:MAX_TACTICS])

        # Add techniques (limit to 5)
        if mitre_techniques:
            # If we have too many techniques, prioritize the simpler ones (fewer dots)
            sorted_techniques = sorted(mitre_techniques, key=lambda x: x.count("."))
            final_tags.extend(sorted_techniques[:MAX_TECHNIQUES])

        # Add CVE tags (limit to 2 most recent)
        if cve_tags:
            # Sort CVEs by year (most recent first) and take top 2
            sorted_cves = sorted(
                cve_tags,
                key=lambda x: x.split("-")[1] if "-" in x else "0000",
                reverse=True,
            )
            final_tags.extend(sorted_cves[:MAX_CVES])

        # Add important non-MITRE tags if we have room
        remaining_slots = MAX_TOTAL_TAGS - len(final_tags)
        final_tags.extend(other_important_tags[:remaining_slots])

        # Add overflow notes if needed
        overflow_notes = []
        if len(mitre_tactics) > MAX_TACTICS:
            overflow_notes.append(f"+{len(mitre_tactics) - MAX_TACTICS}_tactics")
        if len(mitre_techniques) > MAX_TECHNIQUES:
            overflow_notes.append(
                f"+{len(mitre_techniques) - MAX_TECHNIQUES}_techniques"
            )
        if len(cve_tags) > MAX_CVES:
            overflow_notes.append(f"+{len(cve_tags) - MAX_CVES}_cves")

        if overflow_notes and len(final_tags) < MAX_TOTAL_TAGS:
            final_tags.append(f'_note:{",".join(overflow_notes)}')

        return final_tags

    @classmethod
    def get_category(cls, sigma_tags: List[str]) -> str:
        """Determine category based on MITRE ATT&CK tactics and techniques"""
        # First, look for direct tactic matches in the tags
        for tag in sigma_tags:
            if tag.startswith("attack.") and tag in cls.MITRE_TACTIC_MAPPINGS:
                tactic_id = cls.MITRE_TACTIC_MAPPINGS[tag]
                return cls.CATEGORY_MAPPINGS.get(tactic_id, "Other")

        # Check for tactic names that appear as plain text
        for tag in sigma_tags:
            if tag in cls.CATEGORY_MAPPINGS.values():
                return tag

        # If no direct tactic match, derive from technique tags
        for tag in sigma_tags:
            if tag.startswith("attack.t"):
                technique = tag.replace("attack.t", "T").upper()
                # Map common techniques to their primary tactic
                if technique.startswith("T1003"):  # OS Credential Dumping
                    return "Credential Access"
                elif technique.startswith("T1059"):  # Command and Scripting Interpreter
                    return "Execution"
                elif technique.startswith("T1055"):  # Process Injection
                    return "Privilege Escalation"
                elif technique.startswith("T1021"):  # Remote Services
                    return "Lateral Movement"
                elif technique.startswith("T1070"):  # Indicator Removal
                    return "Defense Evasion"
                # Add more common technique-to-tactic mappings as needed

        return "Other"

    @classmethod
    def get_severity_score(cls, sigma_level: str) -> int:
        """Convert Sigma level to Sumo Logic CSE severity score"""
        return cls.SEVERITY_MAPPINGS.get(sigma_level, 4)


class LogSourceMapper:
    """Maps Sigma log sources to Sumo Logic CSE metadata conditions"""

    def __init__(self, field_mapper: FieldMapper):
        self.field_mapper = field_mapper

    def map_logsource(self, logsource: Dict[str, str]) -> str:
        """Convert Sigma logsource to Sumo Logic CSE metadata conditions"""
        mapping_data = self.field_mapper.get_mapping_for_logsource(logsource)
        logsource_conditions = mapping_data.get("logsource_conditions", [])

        return " AND ".join(logsource_conditions)


class SimpleYAMLParser:
    """Simple YAML parser for basic Sigma rules (fallback when PyYAML not available)"""

    @staticmethod
    def parse_simple_yaml(yaml_str: str) -> Dict[str, Any]:
        """Parse simple YAML structure (limited functionality)"""
        result: Dict[str, Any] = {}  # Add type annotation
        lines = yaml_str.strip().split("\n")
        current_key = None
        current_list = None
        indent_stack: List[int] = []  # Reserved for future nested parsing

        for line in lines:
            if not line.strip() or line.strip().startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())
            line = line.strip()

            if line.startswith("- "):
                # List item
                if current_list is not None:
                    current_list.append(line[2:].strip().strip("\"'"))
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if not value:
                    # Key with no value - might be a section or list
                    current_key = key
                    if indent == 0:
                        result[key] = {}
                    continue

                # Handle nested structures
                if indent > 0 and current_key:
                    if current_key not in result:
                        result[current_key] = {}
                    if value.startswith("[") and value.endswith("]"):
                        # Inline list
                        result[current_key][key] = [
                            item.strip().strip("\"'") for item in value[1:-1].split(",")
                        ]
                    else:
                        result[current_key][key] = value.strip("\"'")
                else:
                    if value.startswith("[") and value.endswith("]"):
                        # Inline list
                        result[key] = [
                            item.strip().strip("\"'") for item in value[1:-1].split(",")
                        ]
                    else:
                        result[key] = value.strip("\"'")

        return result


class SigmaToSumoConverter:
    """Main converter class"""

    def __init__(self):
        self.field_mapper = FieldMapper()
        self.logic_translator = DetectionLogicTranslator(self.field_mapper)
        self.metadata_mapper = MetadataMapper()
        self.logsource_mapper = LogSourceMapper(self.field_mapper)
        self.simple_parser = SimpleYAMLParser()

    def convert_sigma_rule(self, sigma_yaml: str) -> ConversionResult:
        """Convert a Sigma rule YAML to Sumo Logic CSE JSON"""
        try:
            # Parse YAML
            if HAS_YAML:
                sigma_rule = yaml.safe_load(sigma_yaml)  # type: ignore
            else:
                print(
                    "⚠️  PyYAML not found, using simple parser (limited functionality)"
                )
                print("💡 Install PyYAML with: pip install PyYAML")
                sigma_rule = self.simple_parser.parse_simple_yaml(sigma_yaml)

            # Validate required fields
            if not sigma_rule.get("title"):
                return ConversionResult(False, errors=["Missing required field: title"])

            if not sigma_rule.get("detection"):
                return ConversionResult(
                    False, errors=["Missing required field: detection"]
                )

            # Set logsource context for field mapping
            if "logsource" in sigma_rule:
                self.logic_translator.set_logsource(sigma_rule["logsource"])

            # Convert detection logic
            detection_expr = self.logic_translator.translate_detection(
                sigma_rule["detection"]
            )

            # Add log source conditions
            if "logsource" in sigma_rule:
                logsource_conditions = self.logsource_mapper.map_logsource(
                    sigma_rule["logsource"]
                )
                if logsource_conditions:
                    detection_expr = f"{logsource_conditions}\nAND {detection_expr}"

            # Map metadata
            tags = self.metadata_mapper.map_tags(sigma_rule.get("tags", []))
            category = self.metadata_mapper.get_category(sigma_rule.get("tags", []))
            severity_score = self.metadata_mapper.get_severity_score(
                sigma_rule.get("level", "medium")
            )

            # Generate descriptions
            author = sigma_rule.get("author", "Unknown")
            description = sigma_rule.get("description", "")
            rule_id = sigma_rule.get("id", "")

            description_expr = description
            if author:
                description_expr += f" Author: {author}."
            if rule_id:
                description_expr += f" Rule ID: {rule_id}"

            # Build API format (only format we need)
            api_json = {
                "fields": {
                    "category": category,
                    "enabled": True,
                    "entitySelectors": [
                        {"expression": "device_hostname", "entityType": "_hostname"}
                    ],
                    "isPrototype": True,
                    "name": sigma_rule["title"],
                    "parentJaskId": None,
                    "summaryExpression": (
                        description[:200] + "..."
                        if len(description) > 200
                        else description
                    ),
                    "tags": tags,
                    "tuningExpressionIds": [],
                    "descriptionExpression": description_expr,
                    "expression": detection_expr,
                    "nameExpression": sigma_rule["title"],
                    "scoreMapping": {
                        "type": "constant",
                        "default": severity_score,
                        "field": None,
                        "mapping": None,
                    },
                    "stream": "record",
                }
            }

            return ConversionResult(
                success=True,
                rule_json=None,  # No longer needed
                api_json=api_json,
                warnings=[],
            )

        except Exception as e:
            return ConversionResult(False, errors=[f"Conversion error: {str(e)}"])

    def convert_file(self, input_file: str, output_dir: str = "output") -> bool:
        """Convert a Sigma rule file to Sumo Logic CSE JSON file"""
        try:
            # Read input file
            input_path = Path(input_file)
            if not input_path.exists():
                print(f"❌ Input file not found: {input_file}")
                return False

            print(f"📖 Reading Sigma rule from: {input_file}")
            with open(input_path, "r", encoding="utf-8") as f:
                sigma_yaml = f.read()

            print(f"📄 File content length: {len(sigma_yaml)} characters")

            # Convert the rule
            print("🔄 Converting rule...")
            result = self.convert_sigma_rule(sigma_yaml)

            if not result.success:
                print("❌ Conversion failed:")
                for error in result.errors or []:
                    print(f"  - {error}")
                return False

            # Get the category for directory structure
            category = result.api_json["fields"]["category"]  # type: ignore

            # Create category-based output directory
            category_dir = (
                Path(output_dir) / "sumo_cse_rules" / category.lower().replace(" ", "_")
            )
            category_dir.mkdir(parents=True, exist_ok=True)
            print(f"📁 Created category directory: {category_dir}")

            # Generate output filename based on input filename
            base_name = input_path.stem
            api_rule_file = category_dir / f"{base_name}.json"

            # Save API rule JSON
            print(f"💾 Saving rule to: {api_rule_file}")
            with open(api_rule_file, "w", encoding="utf-8") as f:
                json.dump(result.api_json, f, indent=2, ensure_ascii=False)

            print("✅ Conversion completed successfully!")
            print(f"📂 Rule saved in category: {category}")

            if result.warnings:
                print("\n⚠️  Warnings:")
                for warning in result.warnings or []:
                    print(f"  - {warning}")

            return True

        except Exception as e:
            print(f"❌ Error during file conversion: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def convert_directory(self, input_dir: str, output_dir: str = "output") -> int:
        """Convert all Sigma rule files in a directory"""
        input_path = Path(input_dir)
        if not input_path.exists():
            print(f"❌ Input directory not found: {input_dir}")
            return 0

        # Find all YAML files
        yaml_files = list(input_path.glob("*.yml")) + list(input_path.glob("*.yaml"))

        if not yaml_files:
            print(f"❌ No YAML files found in: {input_dir}")
            return 0

        print(f"📁 Found {len(yaml_files)} YAML files to convert")

        successful_conversions = 0
        for yaml_file in yaml_files:
            print(f"\n🔄 Converting: {yaml_file.name}")
            if self.convert_file(str(yaml_file), output_dir):
                successful_conversions += 1

        print(
            f"\n✅ Successfully converted {successful_conversions}/{len(yaml_files)} files"
        )
        return successful_conversions


def main():
    """Command line interface"""
    print("🚀 Starting Sigma to Sumo Logic CSE Converter...")

    parser = argparse.ArgumentParser(
        description="Convert Sigma detection rules to Sumo Logic CSE format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert a single file
  python3 sigma_sumo_converter.py -i suspicious_file.yml

  # Convert a single file with custom output directory
  python3 sigma_sumo_converter.py -i suspicious_file.yml -o /path/to/output

  # Convert all YAML files in a directory
  python3 sigma_sumo_converter.py -d /path/to/sigma/rules

  # Convert directory with custom output location
  python3 sigma_sumo_converter.py -d /path/to/sigma/rules -o /path/to/output
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input", help="Input Sigma rule file (.yml or .yaml)")
    group.add_argument(
        "-d", "--directory", help="Input directory containing Sigma rule files"
    )

    parser.add_argument(
        "-o", "--output", default="output", help="Output directory (default: output)"
    )

    args = parser.parse_args()
    print(
        f"📋 Arguments: input={args.input}, directory={args.directory}, output={args.output}"
    )

    converter = SigmaToSumoConverter()
    print("✅ Converter initialized")

    if args.input:
        print(f"🔄 Converting single file: {args.input}")
        success = converter.convert_file(args.input, args.output)
        print(f"🏁 Conversion result: {'Success' if success else 'Failed'}")
        exit(0 if success else 1)
    elif args.directory:
        print(f"🔄 Converting directory: {args.directory}")
        count = converter.convert_directory(args.directory, args.output)
        print(f"🏁 Conversion result: {count} files processed")
        exit(0 if count > 0 else 1)


if __name__ == "__main__":
    main()
