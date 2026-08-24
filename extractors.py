from abc import ABC, abstractmethod
from typing import List
from urllib.parse import urlparse, parse_qsl
import base64
from html.parser import HTMLParser
from models import ResourceData, Finding, Category
from typing import Optional

class BaseExtractor(ABC):
    @abstractmethod
    def extract(self, resource: ResourceData) -> List[Finding]:
        pass


class UrlExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        parsed_url = urlparse(resource.url)
        findings = self._extract_query_params(resource.url, parsed_url.query)
        findings.extend(self._extract_path_segments(resource.url, parsed_url.path))
        return findings

    def _extract_query_params(self, url: str, query: str) -> List[Finding]:
        findings = []
        for key, value in parse_qsl(query):
            decoded = self._try_decode(value)
            if decoded:
                location = f"URL Query Param: {key}"
                findings.append(Finding(url, Category.ENCODED_OBFUSCATED, location, decoded))
        return findings

    def _extract_path_segments(self, url: str, path: str) -> List[Finding]:
        findings = []
        for segment in path.split('/'):
            if not segment:
                continue
            decoded = self._try_decode(segment)
            if decoded:
                location = f"URL Path Segment: {segment}"
                findings.append(Finding(url, Category.ENCODED_OBFUSCATED, location, decoded))
        return findings

    def _try_decode(self, text: str) -> Optional[str]:
        if len(text) < 8:
            return None

        base64_result = self._try_base64_decode(text)
        if base64_result:
            return f"base64:{base64_result}"

        hex_result = self._try_hex_decode(text)
        if hex_result:
            return f"hex:{hex_result}"

        return None

    def _try_base64_decode(self, text: str) -> Optional[str]:
        try:
            padded = text + '=' * (-len(text) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded_str = decoded_bytes.decode('utf-8')
            return decoded_str if decoded_str.isprintable() else None
        except Exception:
            return None

    def _try_hex_decode(self, text: str) -> Optional[str]:
        try:
            decoded_bytes = bytes.fromhex(text)
            decoded_str = decoded_bytes.decode('utf-8')
            return decoded_str if decoded_str.isprintable() else None
        except Exception:
            return None

class ProtocolExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = self._extract_status_code(resource)
        findings.extend(self._extract_headers(resource))
        findings.extend(self._extract_cookies(resource))
        return findings

    def _extract_status_code(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if resource.status_code in [401, 403, 404] and resource.text_content:
            findings.append(Finding(
                source_url=resource.url,
                category=Category.SERVER_PROTOCOL,
                location=f"Status Code {resource.status_code} Body",
                content=resource.text_content[:200]
            ))
        return findings

    def _extract_headers(self, resource: ResourceData) -> List[Finding]:
        findings = []
        interesting_headers = ["x-", "server", "location"]
        for key, value in resource.headers.items():
            if any(key.lower().startswith(p) for p in interesting_headers):
                findings.append(Finding(
                    source_url=resource.url,
                    category=Category.SERVER_PROTOCOL,
                    location=f"Header: {key}",
                    content=value
                ))
        return findings

    def _extract_cookies(self, resource: ResourceData) -> List[Finding]:
        findings = []
        for cookie in resource.cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            findings.append(Finding(
                source_url=resource.url,
                category=Category.SERVER_PROTOCOL,
                location=f"Cookie: {name}",
                content=value
            ))
        return findings

class HiddenContentParser(HTMLParser):
    def __init__(self, url: str):
        super().__init__()
        self.url = url
        self.findings = []

    def handle_comment(self, data: str):
        if data.strip():
            self.findings.append(Finding(self.url, Category.HTML_SOURCE, "HTML Comment", data.strip()))

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = dict(attrs)
        self._check_hidden_inputs(tag, attr_dict)
        self._check_meta_tags(tag, attr_dict)
        self._check_attributes(tag, attrs)
        self._check_hidden_styles(tag, attr_dict)

    def _check_hidden_inputs(self, tag: str, attr_dict: dict):
        if tag == "input" and attr_dict.get("type") == "hidden":
            val = attr_dict.get("value", "")
            name = attr_dict.get("name", "unknown")
            self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Hidden Input: {name}", val))

    def _check_meta_tags(self, tag: str, attr_dict: dict):
        if tag == "meta":
            name = attr_dict.get("name") or attr_dict.get("property") or "unknown"
            val = attr_dict.get("content", "")
            self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Meta Tag: {name}", val))

    def _check_attributes(self, tag: str, attrs: list):
        targets = {'alt', 'title', 'placeholder', 'aria-label', 'srcdoc', 'srcset'}
        for k, v in attrs:
            if not v: 
                continue
            if k in targets or k.startswith('data-'):
                self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Attribute: {tag}[{k}]", v))

    def _check_hidden_styles(self, tag: str, attr_dict: dict):
        style = attr_dict.get("style", "").replace(" ", "").lower()
        if "display:none" in style or "visibility:hidden" in style:
            self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Hidden Style Element: {tag}", str(attr_dict)))

class HtmlExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        if not resource.text_content:
            return []
        
        parser = HiddenContentParser(resource.url)
        try:
            parser.feed(resource.text_content)
        except Exception:
            pass  # Ignore malformed HTML errors
            
        return parser.findings

class JsContextExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        findings.extend(self._extract_storage(resource))
        findings.extend(self._extract_logs(resource))
        findings.extend(self._extract_network(resource))
        findings.extend(self._extract_canvas(resource))
        return findings

    def _extract_storage(self, resource: ResourceData) -> List[Finding]:
        findings = []
        for k, v in resource.local_storage.items():
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"localStorage: {k}", v))
        for k, v in resource.session_storage.items():
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"sessionStorage: {k}", v))
        return findings

    def _extract_logs(self, resource: ResourceData) -> List[Finding]:
        findings = []
        for idx, log in enumerate(resource.console_logs):
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"Console Log [{idx}]", log))
        return findings

    def _extract_network(self, resource: ResourceData) -> List[Finding]:
        findings = []
        for idx, xhr in enumerate(resource.xhr_responses):
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"XHR Response [{idx}]: {xhr.get('url', '')}", xhr.get('body', '')))
        for idx, msg in enumerate(resource.websocket_messages):
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"WebSocket Msg [{idx}]", msg))
        return findings

    def _extract_canvas(self, resource: ResourceData) -> List[Finding]:
        findings = []
        for selector, data_url in resource.canvas_data.items():
            findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"Canvas Data: {selector}", data_url))
        return findings

import re

class MediaExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if not resource.body_bytes:
            return findings
            
        content_type = resource.content_type.lower()
        if content_type.startswith("image/"):
            findings.extend(self._extract_image(resource))
        elif "javascript" in content_type or "css" in content_type:
            findings.extend(self._extract_code(resource))
        return findings

    def _extract_image(self, resource: ResourceData) -> List[Finding]:
        findings = []
        # Raw byte ASCII extraction to catch EXIF and PNG tEXt chunks without external libraries
        strings = re.findall(b'[ -~]{6,}', resource.body_bytes)
        for idx, b_str in enumerate(strings):
            s = b_str.decode('ascii', errors='ignore')
            findings.append(Finding(resource.url, Category.LINKED_RESOURCES, f"Binary String [{idx}]", s))
        return findings

    def _extract_code(self, resource: ResourceData) -> List[Finding]:
        findings = []
        comments = re.findall(r'/\*[\s\S]*?\*/|//.*', resource.text_content)
        for idx, c in enumerate(comments):
            findings.append(Finding(resource.url, Category.LINKED_RESOURCES, f"Code Comment [{idx}]", c))
        return findings

class DecodingExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        texts_to_scan = [("URL", resource.url), ("Body", resource.text_content)]
        
        for k, v in resource.headers.items():
            texts_to_scan.append((f"Header {k}", v))
            
        for cookie in resource.cookies:
            texts_to_scan.append((f"Cookie {cookie.get('name')}", cookie.get('value', '')))
        
        # Look for Base64 sequences (at least 8 chars long)
        base64_regex = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        
        for location, text in texts_to_scan:
            if not text: 
                continue
            for match in base64_regex.finditer(text):
                decoded = self._try_base64_decode(match.group(0))
                if decoded:
                    findings.append(Finding(resource.url, Category.ENCODED_OBFUSCATED, f"{location} Base64", decoded))
        return findings

    def _try_base64_decode(self, text: str) -> Optional[str]:
        try:
            padded = text + '=' * (-len(text) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded_str = decoded_bytes.decode('utf-8')
            if len(decoded_str) > 3 and decoded_str.isprintable():
                return decoded_str
            return None
        except Exception:
            return None
