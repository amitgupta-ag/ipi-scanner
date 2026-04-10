"""Setup configuration for IPI-Scanner."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ipi-scanner",
    version="0.1.0",
    author="IPI-Scanner Contributors",
    author_email="info@ipi-scanner.dev",
    description="Detect Indirect Prompt Injection attacks before your LLM reads them",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/ipi-scanner",
    project_urls={
        "Bug Tracker": "https://github.com/username/ipi-scanner/issues",
        "Documentation": "https://github.com/username/ipi-scanner/blob/main/README.md",
    },
    packages=find_packages(),
    package_data={
        'ipi_scanner': ['patterns.json'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0.0",
        "pdfplumber>=0.10.0",
        "Pillow>=10.0.0",
        "pytesseract>=0.3.10",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ipi-scan=ipi_scanner.cli:main",
        ],
    },
)
