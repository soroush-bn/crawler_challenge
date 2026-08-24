import re
import json
from typing import Optional


class Finder():
    def __init__(self, base_url=""):
        self.base_url = base_url
        self.sample_password = "VISUALPING{0000deadbeef0000}"
        self.password_regex = re.compile(r'VISUALPING\{[0-9a-fA-F]{16}\}')

    def _search_text(self, text: str) -> Optional[str]:
        if not text:
            return None
        for match in self.password_regex.finditer(text):
            found = match.group(0)
            if found != self.sample_password:
                return found
        return None

    def find_password_in_json(self, json_data) -> Optional[str]:
        # Convert dictionaries/lists to string to easily regex them
        if isinstance(json_data, (dict, list)):
            json_str = json.dumps(json_data)
            return self._search_text(json_str)
        elif isinstance(json_data, str):
            return self._search_text(json_data)
        return None

    def find_password_in_html(self, html_content: str) -> Optional[str]:
        return self._search_text(html_content)

    def find_password_in_text(self, text_content: str) -> Optional[str]:
        return self._search_text(text_content)

    def find_password_in_image(self, image_bytes: bytes) -> Optional[str]:
        if not image_bytes:
            return None
        # Search raw bytes decoded as ASCII (covers EXIF, PNG tEXt, JPEG COM, etc.)
        text = image_bytes.decode('ascii', errors='ignore')
        return self._search_text(text)

    def find_password_in_pdf(self, pdf_bytes: bytes) -> Optional[str]:
        if not pdf_bytes:
            return None
        try:
            import pypdf
            import io
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            for page in reader.pages:
                text = page.extract_text()
                found = self._search_text(text)
                if found:
                    return found
        except Exception as e:
            pass
        return None

    def find_password_in_blob(self, blob_bytes: bytes) -> Optional[str]:
        if not blob_bytes:
            return None
            
        # Check if it's a ZIP file (starts with PK\x03\x04)
        if blob_bytes[:4] == b'PK\x03\x04':
            try:
                import zipfile
                import io
                with zipfile.ZipFile(io.BytesIO(blob_bytes)) as z:
                    for filename in z.namelist():
                        with z.open(filename) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            found = self._search_text(content)
                            if found:
                                return found
            except Exception:
                pass
                
        # Attempt naive ASCII decode for uncompressed text in binary blobs
        return self._search_text(blob_bytes.decode('ascii', errors='ignore'))
