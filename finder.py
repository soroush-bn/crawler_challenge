import re
import json
import zipfile
import gzip
import io
from typing import List, Any

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    import zstandard
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


class Finder:
    def __init__(self, base_url: str = "") -> None:
        self.base_url: str = base_url
        self.sample_password: str = "VISUALPING{0000deadbeef0000}"
        self.password_regex: re.Pattern = re.compile(r'VISUALPING\{[0-9a-fA-F]{16}\}')

    def _search_text(self, text: str) -> List[str]:
        """Return all unique non-sample passwords found in text."""
        if not text:
            return []
        results: List[str] = []
        
        for match in self.password_regex.finditer(text):
            found: str = match.group(0)
            if found != self.sample_password and found not in results:
                results.append(found)
                
        return results

    def find_password_in_json(self, json_data: Any) -> List[str]:
        if isinstance(json_data, (dict, list)):
            json_str: str = json.dumps(json_data)
            return self._search_text(json_str)
        elif isinstance(json_data, str):
            return self._search_text(json_data)
        return []

    def find_password_in_html(self, html_content: str) -> List[str]:
        return self._search_text(html_content)

    def find_password_in_text(self, text_content: str) -> List[str]:
        return self._search_text(text_content)

    def find_password_in_image(self, image_bytes: bytes) -> List[str]:
        if not image_bytes:
            return []
        text: str = image_bytes.decode('ascii', errors='ignore')
        return self._search_text(text)

    def find_password_in_pdf(self, pdf_bytes: bytes) -> List[str]:
        if not pdf_bytes or not HAS_PYPDF:
            return []
        results: List[str] = []
        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            for page in reader.pages:
                text: str = page.extract_text()
                for found in self._search_text(text):
                    if found not in results:
                        results.append(found)
        except Exception:
            pass
        return results

    def find_password_in_blob(self, blob_bytes: bytes) -> List[str]:
        if not blob_bytes:
            return []
            
        results: List[str] = []
        
        self._extend_unique(results, self._scan_zip(blob_bytes))
        self._extend_unique(results, self._scan_gzip(blob_bytes))
        self._extend_unique(results, self._scan_brotli(blob_bytes))
        self._extend_unique(results, self._scan_zstd(blob_bytes))
        self._extend_unique(results, self._search_text(blob_bytes.decode('ascii', errors='ignore')))
        
        return results

    def _extend_unique(self, target_list: List[str], source_list: List[str]) -> None:
        for item in source_list:
            if item not in target_list:
                target_list.append(item)

    def _scan_zip(self, blob_bytes: bytes) -> List[str]:
        if blob_bytes[:4] != b'PK\x03\x04':
            return []
        results: List[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(blob_bytes)) as z:
                for filename in z.namelist():
                    with z.open(filename) as f:
                        content: str = f.read().decode('utf-8', errors='ignore')
                        self._extend_unique(results, self._search_text(content))
        except Exception:
            pass
        return results

    def _scan_gzip(self, blob_bytes: bytes) -> List[str]:
        if blob_bytes[:2] != b'\x1f\x8b':
            return []
        try:
            decompressed: bytes = gzip.decompress(blob_bytes)
            return self._search_text(decompressed.decode('utf-8', errors='ignore'))
        except Exception:
            return []

    def _scan_brotli(self, blob_bytes: bytes) -> List[str]:
        if not HAS_BROTLI:
            return []
        try:
            decompressed: bytes = brotli.decompress(blob_bytes)
            return self._search_text(decompressed.decode('utf-8', errors='ignore'))
        except Exception:
            return []

    def _scan_zstd(self, blob_bytes: bytes) -> List[str]:
        if not HAS_ZSTD or blob_bytes[:4] != b'\x28\xb5\x2f\xfd':
            return []
        try:
            dctx = zstandard.ZstdDecompressor()
            decompressed: bytes = dctx.decompress(blob_bytes)
            return self._search_text(decompressed.decode('utf-8', errors='ignore'))
        except Exception:
            return []
