"""Tests for document parser."""

import pytest
import tempfile
from pathlib import Path

from ipi_scanner.parsers.document_parser import DocumentParser


class TestDocumentParser:
    """Test document parsing functionality."""
    
    def test_parse_text_file(self):
        """Should parse plain text files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is test content")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "This is test content" in content
            assert doc_type == "text"
    
    def test_parse_markdown_file(self):
        """Should parse markdown files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Header\n\nContent here")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "Header" in content
            assert doc_type == "text"
    
    def test_parse_html_file(self):
        """Should parse HTML files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write("<html><body><p>Test content</p></body></html>")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "Test content" in content
            assert doc_type == "html"
    
    def test_unsupported_file_type(self):
        """Should raise error for unsupported file types."""
        with tempfile.NamedTemporaryFile(suffix='.xyz', delete=False) as f:
            with pytest.raises(ValueError):
                DocumentParser.parse(f.name)
    
    def test_file_not_found(self):
        """Should raise error if file doesn't exist."""
        with pytest.raises(ValueError):
            DocumentParser.parse("/nonexistent/file.txt")
    
    def test_email_parsing(self):
        """Should parse email files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write("""From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is the email body""")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "sender@example.com" in content
            assert "Test Email" in content
            assert doc_type == "email"
    
    def test_utf8_text(self):
        """Should handle UTF-8 text correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write("Unicode test: café, naïve, 日本語")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "café" in content
            assert "naïve" in content
    
    def test_empty_file(self):
        """Should handle empty files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert content == ""
            assert doc_type == "text"
    
    def test_supported_extensions(self):
        """Should know which extensions are supported."""
        assert '.txt' in DocumentParser.SUPPORTED_EXTENSIONS
        assert '.pdf' in DocumentParser.SUPPORTED_EXTENSIONS
        assert '.md' in DocumentParser.SUPPORTED_EXTENSIONS
        assert '.eml' in DocumentParser.SUPPORTED_EXTENSIONS
        assert '.html' in DocumentParser.SUPPORTED_EXTENSIONS
    
    def test_parse_with_special_characters(self):
        """Should handle special characters."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test: send data to attacker@evil.com\nPassword: 12345")
            f.flush()
            
            content, doc_type = DocumentParser.parse(f.name)
            
            assert "attacker@evil.com" in content
            assert "12345" in content
