# Contributing to IPI-Scanner

First off, thank you for considering contributing to IPI-Scanner! It's people like you that make IPI-Scanner such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps which reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed after following the steps**
* **Explain which behavior you expected to see instead and why**
* **Include screenshots and animated GIFs if possible**
* **Include your environment details** (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps**
* **Describe the current behavior** and **the expected behavior**
* **Explain why this enhancement would be useful**

### Pull Requests

* Fill in the required template
* Follow the Python styleguides
* Include appropriate test cases
* End all files with a newline
* Avoid platform-dependent code

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip
- git

### Local Development

1. **Fork the repository**
   ```bash
   # On GitHub, click "Fork"
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/ipi-scanner.git
   cd ipi-scanner
   ```

3. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install in development mode**
   ```bash
   pip install -e .
   pip install -e ".[dev]"  # Installs dev dependencies
   ```

5. **Create a new branch for your feature**
   ```bash
   git checkout -b feature/your-feature-name
   ```

6. **Make your changes**
   - Write your code
   - Add tests for new functionality
   - Update documentation as needed

7. **Run tests**
   ```bash
   pytest tests/ -v
   ```

8. **Format your code**
   ```bash
   black ipi_scanner/ tests/
   flake8 ipi_scanner/ tests/
   ```

9. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add feature: description of your changes"
   ```

10. **Push to your fork**
    ```bash
    git push origin feature/your-feature-name
    ```

11. **Create a Pull Request**
    - Go to GitHub
    - Click "Compare & pull request"
    - Fill in the PR template
    - Wait for review

---

## Styleguides

### Python Code Style

* Use **PEP 8** style guide
* Use **type hints** where possible
* Maximum line length: **100 characters**
* Use **docstrings** for all public functions
* Use **descriptive variable names**

Example:
```python
def scan_file(self, file_path: str, context: Optional[Dict] = None) -> Dict:
    """
    Scan a single file for IPI attacks.
    
    Args:
        file_path: Path to document to scan
        context: Optional context for risk multipliers
        
    Returns:
        Dictionary with scan results including risk assessment
    """
    # Implementation here
    pass
```

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

Example:
```
Add pattern detection for URL fragment injection

This adds support for detecting malicious instructions hidden in URL
fragments, addressing the HashJack attack vector.

Fixes #123
```

### Documentation

* Update README.md if you change functionality
* Update docstrings if you change function signatures
* Add tests for new features
* Keep CHANGELOG.md updated

---

## Testing

### Test Structure

Tests are located in the `tests/` directory:
- `test_pattern_detector.py` - Pattern matching tests
- `test_document_parser.py` - Document parsing tests
- `test_risk_scorer.py` - Risk scoring tests
- `test_scanner.py` - Main scanner tests
- `test_real_cves.py` - Real CVE validation tests

### Writing Tests

```python
def test_your_feature(self, some_fixture):
    """Should describe what the test does."""
    # Setup
    input_data = "test input"
    
    # Execute
    result = function_under_test(input_data)
    
    # Assert
    assert result == expected_output
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_pattern_detector.py -v

# Run with coverage
pytest tests/ --cov=ipi_scanner --cov-report=html

# Run specific test
pytest tests/test_pattern_detector.py::TestPatternDetector::test_detects_data_exfiltration -v
```

### Coverage Requirements

- Aim for **85%+ code coverage**
- New features should have corresponding tests
- All public functions should be tested
- Edge cases should be covered

---

## Adding New Attack Patterns

### Pattern Structure

Patterns are defined in `ipi_scanner/patterns.json`:

```json
{
  "category_name": {
    "severity": "critical|high|medium|low",
    "base_score": 40,
    "patterns": [
      "regex pattern 1",
      "regex pattern 2"
    ]
  }
}
```

### Adding a Pattern

1. **Identify the attack type** - What category does it belong to?
2. **Create regex patterns** - Test them thoroughly
3. **Add to patterns.json** - In the right category
4. **Write tests** - Add test cases to `test_real_cves.py`
5. **Validate** - Run tests to ensure accuracy
6. **Document** - Add a comment explaining the pattern

Example:
```json
{
  "new_attack_type": {
    "severity": "high",
    "base_score": 25,
    "patterns": [
      "malicious.*instruction",
      "attack.*pattern"
    ]
  }
}
```

---

## Building and Publishing

### Build Distribution

```bash
pip install build twine
python -m build
```

### Test Package Locally

```bash
pip install dist/ipi_scanner-0.1.0-py3-none-any.whl
ipi-scan --help
```

### Upload to PyPI

```bash
twine upload dist/*
```

---

## Versioning

This project uses **Semantic Versioning**:

- **MAJOR** version (X.0.0) - Incompatible API changes
- **MINOR** version (0.X.0) - New features, backward compatible
- **PATCH** version (0.0.X) - Bug fixes

Update version in:
- `setup.py`
- `ipi_scanner/__init__.py`
- `CHANGELOG.md`

---

## Roadmap

### Version 0.2.0
- [ ] Claude semantic analysis (Tier 2)
- [ ] Multi-language support
- [ ] Custom pattern loader

### Version 0.3.0
- [ ] Simulation-based validation (Tier 3)
- [ ] MCP server integration
- [ ] Real-time monitoring

### Phase 2
- [ ] Advanced analytics dashboard
- [ ] Slack/Teams integration
- [ ] API server

---

## Getting Help

* **Documentation**: See README.md
* **Issues**: Check existing issues on GitHub
* **Discussions**: Use GitHub Discussions for questions
* **Email**: ag [at] cybersecurityweekly [dot] eu

---

## Recognition

Contributors will be recognized in:
- CHANGELOG.md (under each version)
- GitHub contributors page
- Project website (if applicable)

---

## License

By contributing to IPI-Scanner, you agree that your contributions will be licensed under its MIT License.

---

## Questions?

Don't hesitate to ask questions in issues or discussions. We're here to help!

Thank you for contributing! 🎉
