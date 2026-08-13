#!/usr/bin/env python3
"""
CIA-Guardian Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cia-guardian",
    version="1.0.0",
    author="CIA-Guardian Team",
    author_email="security@example.com",
    description="Windows Security Hardening Tool based on CIA Triad",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cia-guardian/cia-guardian",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.11",
    install_requires=[
        "jinja2>=3.1.2",
        "fpdf2>=2.7.6",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "cia-guardian=cia_guardian:main",
        ],
    },
    include_package_data=True,
    keywords="security, windows, hardening, compliance, audit, cia-triad",
    project_urls={
        "Bug Reports": "https://github.com/cia-guardian/cia-guardian/issues",
        "Source": "https://github.com/cia-guardian/cia-guardian",
    },
)
