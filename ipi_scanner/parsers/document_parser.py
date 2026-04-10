"""
Document parsing for multiple formats.

Supports: PDF, text, markdown, email, images (with OCR when available).
"""

from pathlib import Path
from typing import Tuple
import mimetypes


class DocumentParser:
    """Parse documents and extract text."""
    
    SUPPORTED_EXTENSIONS = {'.pdf', '.txt', '.md', '.rst', '.html', '.eml', 
                           '.png', '.jpg', '.jpeg', '.webp', '.gif'}
    
    @staticmethod
    def parse(file_path: str) -> Tuple[str, str]:
        """
        Parse a document and return (content, file_type).
        
        Args:
            file_path: Path to document
            
        Returns:
            Tuple of (text_content, file_type)
            
        Raises:
            ValueError: If file type not supported
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension not in DocumentParser.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type: {extension}\n"
                f"Supported: {', '.join(DocumentParser.SUPPORTED_EXTENSIONS)}"
            )
        
        if extension == '.pdf':
            return DocumentParser._parse_pdf(file_path)
        elif extension in ['.png', '.jpg', '.jpeg', '.webp', '.gif']:
            return DocumentParser._parse_image(file_path)
        elif extension == '.eml':
            return DocumentParser._parse_email(file_path)
        elif extension == '.html':
            return DocumentParser._parse_html(file_path)
        else:  # .txt, .md, .rst
            return DocumentParser._parse_text(file_path)
    
    @staticmethod
    def _parse_pdf(file_path: str) -> Tuple[str, str]:
        """Extract text from PDF."""
        try:
            import pdfplumber
        except ImportError:
            raise ImportError(
                "pdfplumber required for PDF support. "
                "Install with: pip install pdfplumber"
            )
        
        text = ""
        try:
            with pdfplumber.open(file_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    text += f"\n--- Page {i+1} ---\n"
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text
        except Exception as e:
            raise ValueError(f"Error reading PDF: {e}")
        
        return text, "pdf"
    
    @staticmethod
    def _parse_image(file_path: str) -> Tuple[str, str]:
        """Extract text from image using basic processing."""
        try:
            from PIL import Image
        except ImportError:
            raise ImportError(
                "Pillow required for image support. "
                "Install with: pip install Pillow"
            )
        
        try:
            img = Image.open(file_path)
            # Try to extract text if pytesseract is available
            try:
                import pytesseract
                text = pytesseract.image_to_string(img)
            except ImportError:
                # Fallback: just note that image was found
                text = f"[Image file: {Path(file_path).name}]\n"
                text += "Note: pytesseract not installed. "
                text += "Install for OCR: pip install pytesseract"
            
            return text, "image"
        except Exception as e:
            raise ValueError(f"Error reading image: {e}")
    
    @staticmethod
    def _parse_text(file_path: str) -> Tuple[str, str]:
        """Read plain text file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            return text, "text"
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    text = f.read()
                return text, "text"
            except Exception as e:
                raise ValueError(f"Error reading text file: {e}")
        except Exception as e:
            raise ValueError(f"Error reading file: {e}")
    
    @staticmethod
    def _parse_email(file_path: str) -> Tuple[str, str]:
        """Parse email file."""
        import email
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                msg = email.message_from_file(f)
            
            text = f"From: {msg.get('From', 'Unknown')}\n"
            text += f"To: {msg.get('To', 'Unknown')}\n"
            text += f"Subject: {msg.get('Subject', 'No subject')}\n"
            text += f"Date: {msg.get('Date', 'Unknown')}\n"
            text += "\n--- Body ---\n"
            
            # Extract body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            text += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    text += payload.decode('utf-8', errors='ignore')
            
            return text, "email"
        except Exception as e:
            raise ValueError(f"Error reading email: {e}")
    
    @staticmethod
    def _parse_html(file_path: str) -> Tuple[str, str]:
        """Parse HTML file."""
        try:
            from html.parser import HTMLParser
        except ImportError:
            # Fallback to basic text extraction
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            return text, "html"
        
        class MLStripper(HTMLParser):
            def __init__(self):
                super().__init__()
                self.reset()
                self.fed = []
            
            def handle_data(self, d):
                self.fed.append(d)
            
            def get_data(self):
                return ''.join(self.fed)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            stripper = MLStripper()
            stripper.feed(html_content)
            text = stripper.get_data()
            
            # Also include the raw HTML for URL fragment analysis
            text += "\n\n--- Raw HTML ---\n" + html_content
            
            return text, "html"
        except Exception as e:
            raise ValueError(f"Error reading HTML: {e}")
