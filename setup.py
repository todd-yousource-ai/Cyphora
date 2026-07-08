"""
ACDA-SDK — Setup
"""

from setuptools import setup, find_packages

setup(
    name="acda-sdk",
    version="1.0.0",
    description="Autonomous Cyber Defense Agent SDK — Consensus-Validated AI Security Architecture",
    author="ACDA Platform Team",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "pydantic>=2.5.3",
        "pydantic-settings>=2.1.0",
        "PyYAML>=6.0.1",
        "jsonschema>=4.21.1",
        "click>=8.1.7",
        "rich>=13.7.0",
        "jinja2>=3.1.3",
        "structlog>=24.1.0",
        "prometheus-client>=0.19.0",
        "httpx>=0.26.0",
    ],
    extras_require={
        "ai": ["openai>=1.12.0", "anthropic>=0.18.1"],
        "graph": ["neo4j>=5.17.0", "networkx>=3.2.1"],
        "streaming": ["aiokafka>=0.10.0"],
        "deploy": ["kubernetes>=29.0.0", "docker>=7.0.0"],
        "dev": [
            "pytest>=7.4.4",
            "pytest-asyncio>=0.23.3",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "black>=24.1.1",
            "isort>=5.13.2",
        ],
        "all": [
            "openai>=1.12.0",
            "anthropic>=0.18.1",
            "neo4j>=5.17.0",
            "networkx>=3.2.1",
            "aiokafka>=0.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "acda=acda.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
