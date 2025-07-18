#!/usr/bin/env python3
"""
Clean setup script for Sigma to Sumo Logic CSE Converter GitHub project
This script creates ONLY the directory structure - no files
"""

from pathlib import Path


def create_directory_structure():
    """Create the complete directory structure"""
    directories = [
        # GitHub integration
        ".github/workflows",
        ".github/ISSUE_TEMPLATE", 
        
        # Documentation
        "docs",
        
        # Field mappings (organized by Sigma taxonomy)
        "field_mappings/windows",
        "field_mappings/linux",
        "field_mappings/cloud",
        "field_mappings/category",
        "field_mappings/network",
        "field_mappings/generic",
        
        # Testing infrastructure
        "tests/fixtures/sample_rules",
        "tests/fixtures/expected_outputs",
        
        # Examples
        "examples/sigma_rules/windows",
        "examples/sigma_rules/linux",
        "examples/sigma_rules/cloud",
        "examples/converted_rules/execution",
        "examples/converted_rules/persistence", 
        "examples/converted_rules/defense_evasion",
        
        # Development tools
        "scripts"
    ]
    
    print("🚀 Creating Sigma to Sumo Logic CSE Converter directory structure...")
    print()
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")
    
    print()
    print("📂 Directory structure created successfully!")
    print()
    print("🎯 Project structure matches our design:")
    print("sigma-sumo-converter/")
    print("├── .github/")
    print("│   ├── workflows/")
    print("│   └── ISSUE_TEMPLATE/")
    print("├── docs/")
    print("├── field_mappings/")
    print("│   ├── windows/")
    print("│   ├── linux/")
    print("│   ├── cloud/")
    print("│   ├── category/")
    print("│   ├── network/")
    print("│   └── generic/")
    print("├── tests/")
    print("│   └── fixtures/")
    print("├── examples/")
    print("│   ├── sigma_rules/")
    print("│   └── converted_rules/")
    print("└── scripts/")
    print()
    print("✅ All directories created - ready for your files!")


def main():
    """Main setup function"""
    create_directory_structure()


if __name__ == "__main__":
    main()