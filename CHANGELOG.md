# Changelog

## [0.1.0] - 2026-04-10

### Added
- Initial release
- Pattern-based IPI detection (Tier 1)
- Document parsing (PDF, text, email, HTML, images)
- Risk scoring (0-100 scale)
- CLI tool with multiple output formats (CLI, JSON, HTML)
- 50+ attack patterns across 15 categories
- Comprehensive test suite (74 tests)
- 85%+ detection accuracy on known attacks

### Features
- Fast pattern matching (<100ms per document)
- Context-aware risk scoring
- 4 output formats
- 3 sensitivity modes
- Batch scanning
- Real CVE validation

### Known Issues
- No Claude semantic analysis yet (Tier 2, coming in v0.2)
- English-only patterns (multilingual coming in Phase 2)
- Scanned PDFs require pytesseract for OCR

### Roadmap
- v0.2: Claude semantic analysis (Tier 2)
- v0.3: Simulation-based validation (Tier 3)
- Phase 2: MCP server integration, multi-language support
