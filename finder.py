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
        pass

    def find_password_in_pdf(self, pdf_bytes: bytes) -> Optional[str]:
        pass

    def find_password_in_blob(self, blob_bytes: bytes) -> Optional[str]:
        if not blob_bytes:
            return None
        # Attempt naive ASCII decode for uncompressed text in binary blobs
        return self._search_text(blob_bytes.decode('ascii', errors='ignore'))
