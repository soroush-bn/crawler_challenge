from dataclasses import dataclass, field
from enum import Enum

class Category(Enum):
    HTML_SOURCE = "HTML SOURCE"
    LINKED_RESOURCES = "LINKED / EMBEDDED RESOURCES"
    JAVASCRIPT_EXECUTED = "ONLY VISIBLE AFTER JAVASCRIPT EXECUTES"
    SERVER_PROTOCOL = "SERVER / PROTOCOL LEVEL"
    UNLINKED_DISCOVERABLE = "DISCOVERABLE BUT NOT LINKED"
    ENCODED_OBFUSCATED = "ENCODED / OBFUSCATED"

@dataclass
class Finding:
    """
    Represents a discovered hidden item matching our extraction criteria.
    """
    source_url: str
    category: Category
    location: str
    content: str

@dataclass
class ResourceData:
    """
    Holds all raw data fetched from a webpage or file required for extraction.
    """
    url: str
    status_code: int = 200
    content_type: str = "text/html"
    body_bytes: bytes = b""
    text_content: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    console_logs: list[str] = field(default_factory=list)
    xhr_responses: list[dict[str, str]] = field(default_factory=list)
    websocket_messages: list[str] = field(default_factory=list)
    canvas_data: dict[str, str] = field(default_factory=dict)
