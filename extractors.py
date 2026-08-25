from abc import ABC, abstractmethod
from typing import List
from urllib.parse import urlparse, parse_qsl
import base64
import os
import struct
import io
import zlib
from html.parser import HTMLParser
from models import ResourceData, Finding, Category
from typing import Optional
from genai.agy_cli import password_in_image

try:
    from PIL import Image
    from PIL.ExifTags import TAGS as EXIF_TAGS, GPSTAGS
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False
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
        for key, value in resource.headers.items():
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
        targets = {'alt', 'title', 'placeholder', 'srcdoc', 'srcset'}
        for k, v in attrs:
            if not v: 
                continue
            if k in targets or k.startswith('data-') or k.startswith('aria-'):
                self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Attribute: {tag}[{k}]", v))
            if k == 'srcdoc':
                self._parse_srcdoc(v)

    def _parse_srcdoc(self, html_content: str):
        sub_parser = HiddenContentParser(self.url)
        try:
            sub_parser.feed(html_content)
            self.findings.extend(sub_parser.findings)
        except Exception:
            pass

    def _check_hidden_styles(self, tag: str, attr_dict: dict):
        style = attr_dict.get("style", "").replace(" ", "").lower()
        if "display:none" in style or "visibility:hidden" in style:
            self.findings.append(Finding(self.url, Category.HTML_SOURCE, f"Hidden Style Element: {tag}", str(attr_dict)))

class HtmlExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if getattr(resource, 'inner_text', None):
            findings.append(Finding(
                source_url=resource.url,
                category=Category.HTML_SOURCE,
                location="Rendered DOM Text",
                content=resource.inner_text
            ))

        if not resource.text_content:
            return findings
        
        parser = HiddenContentParser(resource.url)
        try:
            parser.feed(resource.text_content)
        except Exception:
            pass  # Ignore malformed HTML errors
            
        findings.extend(parser.findings)
        return findings

class JsContextExtractor(BaseExtractor):
    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        findings.extend(self._extract_storage(resource))
        findings.extend(self._extract_logs(resource))
        findings.extend(self._extract_network(resource))
        findings.extend(self._extract_canvas(resource))
        findings.extend(self._extract_computed_styles(resource))
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
        
    def _extract_computed_styles(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if hasattr(resource, 'computed_styles'):
            for idx, style in enumerate(resource.computed_styles):
                findings.append(Finding(resource.url, Category.JAVASCRIPT_EXECUTED, f"Computed Style [{idx}]", style))
        return findings

import re

class MediaExtractor(BaseExtractor):
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg', '.tiff'}
    DATA_DIR = os.path.join(".", "data")

    def __init__(self, enable_ai=False):
        self.enable_ai = enable_ai

    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if not resource.body_bytes:
            return findings

        is_image = self._is_image(resource)
        content_type = resource.content_type.lower()

        if is_image:
            findings.extend(self._extract_image(resource))
            findings.extend(self._agi_image_extract(resource))
            findings.extend(self._extract_lsb_steganography(resource.url, resource.body_bytes))
        elif "javascript" in content_type or "css" in content_type:
            findings.extend(self._extract_code(resource))
        elif self._is_font(content_type, resource.url):
            findings.extend(self._extract_font_metadata(resource))
            
        # Post-process all extracted media metadata strings:
        # If a bare 16-character hex string is found, wrap it in VISUALPING{...}
        # so the downstream finder regex will detect it.
        hex_pattern = re.compile(r'(?<!VISUALPING\{)\b([a-fA-F0-9]{16})\b(?!\})')
        for f in findings:
            if isinstance(f.content, str):
                f.content = hex_pattern.sub(r'VISUALPING{\1}', f.content)
                
        return findings

    def _is_font(self, content_type: str, url: str) -> bool:
        font_types = {'font/', 'application/font', 'application/x-font',
                      'application/vnd.ms-fontobject'}
        if any(content_type.startswith(ft) for ft in font_types):
            return True
        font_extensions = {'.woff', '.woff2', '.ttf', '.otf', '.eot'}
        url_path = url.split("?")[0]
        ext = os.path.splitext(url_path)[1].lower()
        return ext in font_extensions

    def _is_image(self, resource: ResourceData) -> bool:
        if resource.content_type.lower().startswith("image/"):
            return True
        url_path = resource.url.split("?")[0]
        ext = os.path.splitext(url_path)[1].lower()
        return ext in self.IMAGE_EXTENSIONS

    def _agi_image_extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        if not self.enable_ai:
            return findings
            
        filename = resource.url.split("/")[-1].split("?")[0]
        if not filename:
            return findings
        
        for root, dirs, files in os.walk(self.DATA_DIR):
            if filename in files:
                result = password_in_image(root, filename)
                if result:
                    findings.append(Finding(resource.url, Category.LINKED_RESOURCES, "Password Found in Image", result))
                break
        return findings

    def _extract_image(self, resource: ResourceData) -> List[Finding]:
        findings = []
        data = resource.body_bytes
        url = resource.url

        # 1. EXIF metadata via Pillow (JPEG, TIFF, WebP, PNG)
        findings.extend(self._extract_exif(url, data))

        # 2. PNG text chunks (tEXt, zTXt, iTXt) — parsed manually from bytes
        if data[:4] == b'\x89PNG':
            findings.extend(self._extract_png_text_chunks(url, data))

        # 3. JPEG COM (comment) markers
        if data[:2] == b'\xff\xd8':
            findings.extend(self._extract_jpeg_comments(url, data))

        # 4. XMP embedded XML/RDF
        findings.extend(self._extract_xmp(url, data))

        # 5. Trailing data after end-of-image (hidden appended content)
        findings.extend(self._extract_trailing_data(url, data))

        # 6. Fallback: raw ASCII string scan for anything the above missed
        findings.extend(self._extract_ascii_strings(url, data))

        return findings

    # ── EXIF via Pillow ──────────────────────────────────────────────

    def _extract_exif(self, url: str, data: bytes) -> List[Finding]:
        if not HAS_PILLOW:
            return []
        findings = []
        try:
            img = Image.open(io.BytesIO(data))
            exif_data = img.getexif()
            if not exif_data:
                return findings

            for tag_id, value in exif_data.items():
                tag_name = EXIF_TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                # Skip huge binary blobs (thumbnails, maker notes)
                if isinstance(value, bytes) and len(value) > 256:
                    continue
                str_val = self._safe_str(value)
                if str_val:
                    findings.append(Finding(url, Category.LINKED_RESOURCES,
                                            f"EXIF: {tag_name}", str_val))

            # GPS sub-IFD
            gps_info = exif_data.get_ifd(0x8825)
            if gps_info:
                for gps_tag_id, gps_val in gps_info.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, f"GPSTag_0x{gps_tag_id:04X}")
                    str_val = self._safe_str(gps_val)
                    if str_val:
                        findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                f"EXIF GPS: {gps_tag_name}", str_val))

            # UserComment (IFD 0x8769 → tag 0x9286) — can be UTF-16
            exif_ifd = exif_data.get_ifd(0x8769)
            if exif_ifd:
                for tag_id, value in exif_ifd.items():
                    tag_name = EXIF_TAGS.get(tag_id, f"ExifTag_0x{tag_id:04X}")
                    if isinstance(value, bytes) and len(value) > 256:
                        continue
                    str_val = self._safe_str(value)
                    if str_val:
                        findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                f"EXIF IFD: {tag_name}", str_val))

            # Image info dict (PNG textual data via Pillow)
            if hasattr(img, 'info') and img.info:
                for key, val in img.info.items():
                    if key in ('exif', 'icc_profile', 'gamma', 'dpi'):
                        continue  # skip binary / numeric meta
                    str_val = self._safe_str(val)
                    if str_val:
                        findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                f"Image Info: {key}", str_val))
        except Exception:
            pass
        return findings

    # ── PNG tEXt / zTXt / iTXt chunks ────────────────────────────────

    def _extract_png_text_chunks(self, url: str, data: bytes) -> List[Finding]:
        """Parse PNG chunks directly from bytes to catch tEXt, zTXt, iTXt."""
        findings = []
        TEXT_CHUNK_TYPES = {b'tEXt', b'zTXt', b'iTXt'}
        offset = 8  # skip PNG signature

        while offset + 8 <= len(data):
            try:
                chunk_len = struct.unpack('>I', data[offset:offset+4])[0]
                chunk_type = data[offset+4:offset+8]
                chunk_data = data[offset+8:offset+8+chunk_len]
                offset += 12 + chunk_len  # 4 len + 4 type + data + 4 crc

                if chunk_type not in TEXT_CHUNK_TYPES:
                    if chunk_type == b'IEND':
                        break
                    continue

                if chunk_type == b'tEXt':
                    sep = chunk_data.find(b'\x00')
                    if sep != -1:
                        key = chunk_data[:sep].decode('latin-1', errors='replace')
                        val = chunk_data[sep+1:].decode('latin-1', errors='replace')
                        findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                f"PNG tEXt: {key}", val))

                elif chunk_type == b'zTXt':
                    sep = chunk_data.find(b'\x00')
                    if sep != -1:
                        key = chunk_data[:sep].decode('latin-1', errors='replace')
                        # byte after null is compression method (0 = deflate), then compressed text
                        compressed = chunk_data[sep+2:]
                        try:
                            val = zlib.decompress(compressed).decode('latin-1', errors='replace')
                            findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                    f"PNG zTXt: {key}", val))
                        except Exception:
                            pass

                elif chunk_type == b'iTXt':
                    sep = chunk_data.find(b'\x00')
                    if sep != -1:
                        key = chunk_data[:sep].decode('utf-8', errors='replace')
                        # After key null: compression_flag(1) compression_method(1) lang\0 translated_key\0 text
                        rest = chunk_data[sep+1:]
                        if len(rest) >= 2:
                            comp_flag = rest[0]
                            rest = rest[2:]  # skip compression flag + method
                            # skip language tag
                            null1 = rest.find(b'\x00')
                            if null1 != -1:
                                rest = rest[null1+1:]
                                # skip translated keyword
                                null2 = rest.find(b'\x00')
                                if null2 != -1:
                                    text_data = rest[null2+1:]
                                    if comp_flag:
                                        try:
                                            text_data = zlib.decompress(text_data)
                                        except Exception:
                                            pass
                                    val = text_data.decode('utf-8', errors='replace')
                                    findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                            f"PNG iTXt: {key}", val))
            except Exception:
                break
        return findings

    # ── JPEG COM markers ─────────────────────────────────────────────

    def _extract_jpeg_comments(self, url: str, data: bytes) -> List[Finding]:
        """Scan for JPEG COM (0xFFFE) markers in raw bytes."""
        findings = []
        offset = 2  # skip SOI

        while offset + 4 <= len(data):
            if data[offset] != 0xFF:
                break
            marker = data[offset:offset+2]

            if marker == b'\xff\xd9':  # EOI
                break
            if marker == b'\xff\xda':  # SOS — start of scan data, stop parsing markers
                break

            seg_len = struct.unpack('>H', data[offset+2:offset+4])[0]

            if marker == b'\xff\xfe':  # COM
                comment = data[offset+4:offset+2+seg_len]
                try:
                    text = comment.decode('utf-8')
                except UnicodeDecodeError:
                    text = comment.decode('latin-1', errors='replace')
                if text.strip():
                    findings.append(Finding(url, Category.LINKED_RESOURCES,
                                            "JPEG Comment", text.strip()))

            offset += 2 + seg_len

        return findings

    # ── XMP (embedded XML/RDF) ───────────────────────────────────────

    def _extract_xmp(self, url: str, data: bytes) -> List[Finding]:
        """Extract XMP XML embedded in image files (JPEG, PNG, TIFF, etc.)."""
        findings = []
        # XMP is stored between <x:xmpmeta> tags or with the XMP namespace
        xmp_start_markers = [b'<x:xmpmeta', b'<rdf:RDF']
        xmp_end_markers = [b'</x:xmpmeta>', b'</rdf:RDF>']

        for start_tag, end_tag in zip(xmp_start_markers, xmp_end_markers):
            start = data.find(start_tag)
            if start == -1:
                continue
            end = data.find(end_tag, start)
            if end == -1:
                continue
            xmp_bytes = data[start:end + len(end_tag)]
            try:
                xmp_text = xmp_bytes.decode('utf-8', errors='replace')
            except Exception:
                continue

            # Extract key fields from XMP via simple regex (avoids lxml dependency)
            import re as _re
            # dc:description, dc:creator, dc:title, xmp:Label, etc.
            tag_patterns = [
                (r'<dc:description[^>]*>\s*<rdf:Alt[^>]*>\s*<rdf:li[^>]*>(.+?)</rdf:li>', 'XMP dc:description'),
                (r'<dc:creator[^>]*>\s*<rdf:Seq[^>]*>\s*<rdf:li[^>]*>(.+?)</rdf:li>', 'XMP dc:creator'),
                (r'<dc:title[^>]*>\s*<rdf:Alt[^>]*>\s*<rdf:li[^>]*>(.+?)</rdf:li>', 'XMP dc:title'),
                (r'<dc:subject[^>]*>\s*<rdf:Bag[^>]*>(.*?)</rdf:Bag>', 'XMP dc:subject'),
                (r'xmp:Label="([^"]+)"', 'XMP xmp:Label'),
                (r'<xmp:Label>(.+?)</xmp:Label>', 'XMP xmp:Label'),
                (r'photoshop:Instructions="([^"]+)"', 'XMP photoshop:Instructions'),
                (r'<photoshop:Instructions>(.+?)</photoshop:Instructions>', 'XMP photoshop:Instructions'),
            ]
            for pattern, label in tag_patterns:
                for match in _re.finditer(pattern, xmp_text, _re.DOTALL):
                    val = match.group(1).strip()
                    if val:
                        findings.append(Finding(url, Category.LINKED_RESOURCES, label, val))

            # Also emit the full XMP block (trimmed) for the finder to search
            if len(xmp_text) <= 2000:
                findings.append(Finding(url, Category.LINKED_RESOURCES, "XMP Raw", xmp_text))
            else:
                findings.append(Finding(url, Category.LINKED_RESOURCES, "XMP Raw (truncated)",
                                        xmp_text[:2000]))
            break  # only process the first XMP block

        return findings

    # ── Trailing data after end-of-image ─────────────────────────────

    def _extract_trailing_data(self, url: str, data: bytes) -> List[Finding]:
        """Check for data appended after the logical end of the image."""
        findings = []

        # PNG: data after IEND chunk
        iend = data.find(b'IEND')
        if iend != -1:
            # IEND chunk is: 4-byte length (0) + 'IEND' + 4-byte CRC = 12 bytes total
            end_pos = iend + 8  # skip 'IEND' + CRC
            if end_pos < len(data):
                trailing = data[end_pos:]
                if len(trailing) > 4:  # ignore trivial padding
                    printable = trailing.decode('latin-1', errors='replace')
                    findings.append(Finding(url, Category.LINKED_RESOURCES,
                                            f"PNG Trailing Data ({len(trailing)} bytes)", printable[:500]))

        # JPEG: data after EOI marker (0xFFD9)
        elif data[:2] == b'\xff\xd8':
            eoi = data.rfind(b'\xff\xd9')
            if eoi != -1:
                end_pos = eoi + 2
                if end_pos < len(data):
                    trailing = data[end_pos:]
                    if len(trailing) > 4:
                        printable = trailing.decode('latin-1', errors='replace')
                        findings.append(Finding(url, Category.LINKED_RESOURCES,
                                                f"JPEG Trailing Data ({len(trailing)} bytes)", printable[:500]))

        return findings

    # ── Fallback ASCII string scan ───────────────────────────────────

    def _extract_ascii_strings(self, url: str, data: bytes) -> List[Finding]:
        """Raw byte ASCII extraction — catches anything the structured parsers missed."""
        findings = []
        strings = re.findall(b'[ -~]{8,}', data)
        for idx, b_str in enumerate(strings):
            s = b_str.decode('ascii', errors='ignore')
            findings.append(Finding(url, Category.LINKED_RESOURCES, f"Binary String [{idx}]", s))
        return findings

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _safe_str(value) -> Optional[str]:
        """Convert an EXIF value to a string, returning None for empty/uninteresting data."""
        if value is None:
            return None
        if isinstance(value, bytes):
            # Try UTF-8 first, fall back to latin-1
            for enc in ('utf-8', 'latin-1'):
                try:
                    s = value.decode(enc)
                    return s.strip() if s.strip() else None
                except UnicodeDecodeError:
                    continue
            return None
        s = str(value).strip()
        return s if s else None

    def _extract_font_metadata(self, resource: ResourceData) -> List[Finding]:
        """Extract name table strings from font files using fontTools or UTF-16 decoding."""
        findings = []
        data = resource.body_bytes
        url = resource.url

        try:
            import fontTools.ttLib
            import io
            font = fontTools.ttLib.TTFont(io.BytesIO(data))
            if 'name' in font:
                for record in font['name'].names:
                    s = record.toUnicode()
                    if s:
                        findings.append(Finding(url, Category.LINKED_RESOURCES, f"Font Name Table: {record.nameID}", s))
        except Exception:
            pass

        for encoding in ('utf-16-be', 'utf-16-le'):
            try:
                decoded = data.decode(encoding, errors='ignore')
                strings = re.findall(r'[ -~]{4,}', decoded)
                for idx, s in enumerate(strings):
                    findings.append(Finding(
                        url, Category.LINKED_RESOURCES,
                        f"Font String ({encoding}) [{idx}]", s))
            except Exception:
                pass

        return findings

    def _extract_lsb_steganography(self, url: str, data: bytes) -> List[Finding]:
        """Decode least-significant bits of pixel channels into ASCII."""
        if not HAS_PILLOW:
            return []
        findings = []
        try:
            img = Image.open(io.BytesIO(data))
            if img.mode not in ('RGB', 'RGBA', 'L'):
                img = img.convert('RGB')
            pixels = list(img.getdata())

            bits = []
            for pixel in pixels:
                if isinstance(pixel, int):
                    bits.append(pixel & 1)
                else:
                    for channel in pixel[:3]:
                        bits.append(channel & 1)

            byte_array = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit in bits[i:i + 8]:
                    byte_val = (byte_val << 1) | bit
                byte_array.append(byte_val)

            decoded = byte_array.decode('ascii', errors='ignore')
            flag_pattern = re.compile(r'VISUALPING\{[0-9a-fA-F]{16}\}')
            for match in flag_pattern.finditer(decoded):
                findings.append(Finding(
                    url, Category.LINKED_RESOURCES,
                    "LSB Steganography", match.group(0)))
        except Exception:
            pass
        return findings

    def _extract_code(self, resource: ResourceData) -> List[Finding]:
        findings = []
        comments = re.findall(r'/\*[\s\S]*?\*/|//.*', resource.text_content)
        for idx, c in enumerate(comments):
            findings.append(Finding(resource.url, Category.LINKED_RESOURCES, f"Code Comment [{idx}]", c))
        return findings

class DecodingExtractor(BaseExtractor):
    FLAG_SEARCH_PATTERN = re.compile(r'VISUALPING\{[0-9a-fA-F]{16}\}')

    def extract(self, resource: ResourceData) -> List[Finding]:
        findings = []
        texts_to_scan = self._collect_texts(resource)

        findings.extend(self._scan_base64(resource.url, texts_to_scan))
        findings.extend(self._scan_rot13(resource.url, texts_to_scan))
        findings.extend(self._scan_hex_strings(resource.url, texts_to_scan))
        findings.extend(self._scan_reversed(resource.url, texts_to_scan))
        findings.extend(self._scan_url_encoded(resource.url, texts_to_scan))
        findings.extend(self._scan_char_arrays(resource.url, texts_to_scan))
        findings.extend(self._scan_escapes(resource.url, texts_to_scan))
        findings.extend(self._scan_css_escapes(resource.url, texts_to_scan))
        findings.extend(self._scan_concatenated(resource.url, texts_to_scan))

        return findings

    def _collect_texts(self, resource: ResourceData) -> list[tuple[str, str]]:
        texts = [("URL", resource.url), ("Body", resource.text_content)]
        if getattr(resource, 'inner_text', None):
            texts.append(("Rendered Text", resource.inner_text))

        for k, v in resource.headers.items():
            texts.append((f"Header {k}", v))

        for cookie in resource.cookies:
            texts.append((f"Cookie {cookie.get('name')}", cookie.get('value', '')))

        for k, v in resource.local_storage.items():
            texts.append((f"localStorage {k}", v))

        for k, v in resource.session_storage.items():
            texts.append((f"sessionStorage {k}", v))

        for idx, log in enumerate(resource.console_logs):
            texts.append((f"Console Log [{idx}]", log))

        for idx, msg in enumerate(resource.websocket_messages):
            texts.append((f"WebSocket Msg [{idx}]", msg))

        for idx, xhr in enumerate(resource.xhr_responses):
            texts.append((f"Intercepted Response [{idx}]", xhr.get('body', '')))
            
        if hasattr(resource, 'computed_styles'):
            for idx, style in enumerate(resource.computed_styles):
                texts.append((f"Computed Style [{idx}]", style))

        return texts

    def _scan_base64(self, url: str, texts: list) -> List[Finding]:
        findings = []
        base64_regex = re.compile(
            r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

        for location, text in texts:
            if not text:
                continue
            for match in base64_regex.finditer(text):
                decoded = self._try_base64_decode(match.group(0))
                if decoded:
                    findings.append(Finding(
                        url, Category.ENCODED_OBFUSCATED,
                        f"{location} Base64", decoded))
                    recursive = self._try_base64_decode(decoded)
                    if recursive:
                        findings.append(Finding(
                            url, Category.ENCODED_OBFUSCATED,
                            f"{location} Base64 (recursive)", recursive))
        return findings

    def _scan_rot13(self, url: str, texts: list) -> List[Finding]:
        """Apply ROT13 to all text and search for the flag pattern."""
        import codecs
        findings = []
        for location, text in texts:
            if not text:
                continue
            decoded = codecs.decode(text, 'rot_13')
            for match in self.FLAG_SEARCH_PATTERN.finditer(decoded):
                findings.append(Finding(
                    url, Category.ENCODED_OBFUSCATED,
                    f"{location} ROT13", match.group(0)))
        return findings

    def _scan_hex_strings(self, url: str, texts: list) -> List[Finding]:
        """Find long hex sequences in text, decode them, and search."""
        hex_regex = re.compile(r'(?:[0-9a-fA-F]{2}){8,}')
        findings = []
        for location, text in texts:
            if not text:
                continue
            for match in hex_regex.finditer(text):
                try:
                    decoded_bytes = bytes.fromhex(match.group(0))
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded_str) > 3:
                        for flag in self.FLAG_SEARCH_PATTERN.finditer(decoded_str):
                            findings.append(Finding(
                                url, Category.ENCODED_OBFUSCATED,
                                f"{location} Hex", flag.group(0)))
                except Exception:
                    pass
        return findings

    def _scan_reversed(self, url: str, texts: list) -> List[Finding]:
        """Reverse all text and search for the flag pattern."""
        findings = []
        for location, text in texts:
            if not text:
                continue
            reversed_text = text[::-1]
            for match in self.FLAG_SEARCH_PATTERN.finditer(reversed_text):
                findings.append(Finding(
                    url, Category.ENCODED_OBFUSCATED,
                    f"{location} Reversed", match.group(0)))
        return findings

    def _scan_url_encoded(self, url: str, texts: list) -> List[Finding]:
        """URL-decode text and search for the flag pattern."""
        from urllib.parse import unquote
        findings = []
        for location, text in texts:
            if not text or '%' not in text:
                continue
            decoded = unquote(text)
            if decoded != text:
                for match in self.FLAG_SEARCH_PATTERN.finditer(decoded):
                    findings.append(Finding(
                        url, Category.ENCODED_OBFUSCATED,
                        f"{location} URL-decoded", match.group(0)))
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

    def _scan_char_arrays(self, url: str, texts: list) -> List[Finding]:
        """Detect arrays of character codes and convert them back to ASCII strings."""
        findings = []
        # Matches brackets containing at least 10 comma-separated integers (e.g. [86, 73, 83, ...])
        array_regex = re.compile(r'\[\s*(?:\d{2,3}\s*,\s*){10,}\d{2,3}\s*\]')
        
        for location, text in texts:
            if not text:
                continue
            for match in array_regex.finditer(text):
                try:
                    # Remove brackets and split by comma
                    nums_str = match.group(0)[1:-1].split(',')
                    nums = [int(x.strip()) for x in nums_str]
                    
                    # Convert valid ASCII ranges
                    decoded = "".join(chr(n) for n in nums if 32 <= n <= 126)
                    
                    for flag in self.FLAG_SEARCH_PATTERN.finditer(decoded):
                        findings.append(Finding(
                            url, Category.ENCODED_OBFUSCATED,
                            f"{location} Char Array", flag.group(0)))
                except Exception:
                    pass
        return findings

    def _scan_escapes(self, url: str, texts: list) -> List[Finding]:
        """Decode Unicode escapes (\u0056) and HTML entities (&#86;) and search for the flag."""
        findings = []
        import html
        import codecs
        
        for location, text in texts:
            if not text:
                continue
            
            # 1. HTML Unescape
            try:
                unescaped = html.unescape(text)
                if unescaped != text:
                    for match in self.FLAG_SEARCH_PATTERN.finditer(unescaped):
                        findings.append(Finding(
                            url, Category.ENCODED_OBFUSCATED,
                            f"{location} HTML Entities", match.group(0)))
            except Exception:
                pass
                
            # 2. Unicode/Hex escapes (\u0056, \x56)
            try:
                # Use unicode_escape codec on raw bytes to unescape
                escaped_bytes = text.encode('utf-8', errors='ignore')
                decoded_escapes = codecs.decode(escaped_bytes, 'unicode_escape').decode('utf-8', errors='ignore')
                if decoded_escapes != text:
                    for match in self.FLAG_SEARCH_PATTERN.finditer(decoded_escapes):
                        findings.append(Finding(
                            url, Category.ENCODED_OBFUSCATED,
                            f"{location} String Escapes", match.group(0)))
            except Exception:
                pass
                
        return findings

    def _scan_css_escapes(self, url: str, texts: list) -> List[Finding]:
        """Decode CSS escapes (e.g. \0056) and search for the flag."""
        findings = []
        # CSS escape matches backslash followed by 1-6 hex digits and an optional space
        css_escape_regex = re.compile(r'\\([0-9a-fA-F]{1,6})\s?')
        
        for location, text in texts:
            if not text or '\\' not in text:
                continue
                
            try:
                def replace_escape(match):
                    return chr(int(match.group(1), 16))
                
                decoded = css_escape_regex.sub(replace_escape, text)
                if decoded != text:
                    for match in self.FLAG_SEARCH_PATTERN.finditer(decoded):
                        findings.append(Finding(
                            url, Category.ENCODED_OBFUSCATED,
                            f"{location} CSS Escapes", match.group(0)))
            except Exception:
                pass
        return findings

    def _scan_concatenated(self, url: str, texts: list) -> List[Finding]:
        """Strip JS string concatenation (e.g. 'VIS' + 'UAL' + 'PING') before scanning."""
        findings = []
        # Matches closing quote, optional spaces, plus, optional spaces, opening quote
        concat_regex = re.compile(r'[\'"]\s*\+\s*[\'"]')
        
        for location, text in texts:
            if not text:
                continue
            
            # Fast fail if no + symbol exists
            if '+' not in text:
                continue
                
            de_concatenated = concat_regex.sub('', text)
            if de_concatenated != text:
                for match in self.FLAG_SEARCH_PATTERN.finditer(de_concatenated):
                    findings.append(Finding(
                        url, Category.ENCODED_OBFUSCATED,
                        f"{location} Concatenated String", match.group(0)))
                        
        return findings
