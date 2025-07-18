#!/usr/bin/env python3
"""
Setup script for Sigma to Sumo Logic CSE Converter
"""

import os

from setuptools import find_packages, setup


# Read README for long description
def read_readme():
    """Read README.md file"""
    here = os.path.abspath(os.path.dirname(__file__))
    try:
        with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Sigma to Sumo Logic CSE Rule Converter"


# Read requirements
def read_requirements():
    """Read requirements.txt file"""
    here = os.path.abspath(os.path.dirname(__file__))
    try:
        with open(os.path.join(here, "requirements.txt"), encoding="utf-8") as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        return ["PyYAML>=6.0"]


setup(
    name="sigma-sumo-converter",
    version="1.0.0",
    author="steve-jones-sp",
    author_email="steve.jones@sailpoint.com",
    description="Convert Sigma detection rules to Sumo Logic CSE format",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/steve-jones-sp/sigma-sumo-converter",
    project_urls={
        "Bug Reports": "https://github.com/steve-jones-sp/sigma-sumo-converter/issues",
        "Source": "https://github.com/steve-jones-sp/sigma-sumo-converter",
        "Documentation": "https://github.com/steve-jones-sp/sigma-sumo-converter/docs",
    },
    py_modules=["sigma_sumo_converter"],
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="sigma sumo-logic cse siem detection rules security cybersecurity",
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sigma-sumo-converter=sigma_sumo_converter:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["field_mappings/**/*.json", "README.md", "LICENSE"],
    },
    zip_safe=False,
)
