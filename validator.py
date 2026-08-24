import re
import math
from dataclasses import dataclass
from typing import Optional
from consts import FLAG_PATTERN, KNOWN_DECOY


@dataclass
class ValidationResult:
    password: str
    is_valid: bool
    reason: str
    source_url: str
    confidence: str = "high"


class PasswordValidator:
    KNOWN_PLACEHOLDERS = {
        KNOWN_DECOY,
        "VISUALPING{0000000000000000}",
        "VISUALPING{ffffffffffffffff}",
        "VISUALPING{FFFFFFFFFFFFFFFF}",
        "VISUALPING{1234567890abcdef}",
        "VISUALPING{1234567890ABCDEF}",
        "VISUALPING{abcdefabcdefabcd}",
    }

    MIN_HEX_ENTROPY = 1.5

    def __init__(self):
        self.accepted_passwords: set[str] = set()
        self.seen_sources: dict[str, list[str]] = {}

    def validate(self, password: str, source_url: str, source_bytes: Optional[bytes] = None,
                 verified_by_agent: bool = False) -> ValidationResult:

        if not self._matches_format(password):
            return self._reject(password, source_url, "does not match required format")

        if self._is_placeholder(password):
            return self._reject(password, source_url, "known decoy or placeholder pattern")

        if not self._has_sufficient_entropy(password):
            return self._reject(password, source_url,
                                "hex portion has too little entropy — likely a placeholder")

        # if verified_by_agent and not self._exists_in_source(password, source_bytes):
        #     return self._reject(password, source_url,
        #                         "AI-reported but not found in raw source bytes, likely hallucination")

        if password in self.accepted_passwords:
            self._record_source(password, source_url)
            return self._reject(password, source_url, "already found from another location")

        # Accepted
        self.accepted_passwords.add(password)
        self._record_source(password, source_url)

        confidence = self._assess_confidence(password, source_url)
        return ValidationResult(password, True, "valid", source_url, confidence)

    def _matches_format(self, password: str) -> bool:
        return bool(FLAG_PATTERN.match(password))

    def _is_placeholder(self, password: str) -> bool:
        return password in self.KNOWN_PLACEHOLDERS

    def _has_sufficient_entropy(self, password: str) -> bool:
        """Check Shannon entropy of the 16-char hex portion inside the braces."""
        match = re.search(r'\{([0-9a-fA-F]{16})\}', password)
        if not match:
            return False
        hex_part = match.group(1).lower()
        entropy = self._shannon_entropy(hex_part)
        return entropy >= self.MIN_HEX_ENTROPY

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _is_duplicate(self, password: str) -> bool:
        return password in self.accepted_passwords

    def _exists_in_source(self, password: str, source_bytes: Optional[bytes]) -> bool:
        if source_bytes is None:
            return False
        return password.encode() in source_bytes

    def _record_source(self, password: str, source_url: str):
        self.seen_sources.setdefault(password, []).append(source_url)

    def _assess_confidence(self, password: str, source_url: str) -> str:
        """Heuristic confidence level based on available signals."""
        sources = self.seen_sources.get(password, [])
        # Cross-source confirmation = highest confidence
        if len(sources) >= 2:
            return "confirmed"

        hex_match = re.search(r'\{([0-9a-fA-F]{16})\}', password)
        if hex_match:
            entropy = self._shannon_entropy(hex_match.group(1).lower())
            if entropy >= 3.0:
                return "high"
            elif entropy >= 2.0:
                return "medium"
        return "low"

    def _reject(self, password: str, source_url: str, reason: str) -> ValidationResult:
        # Do NOT add to accepted_passwords — only record the source for tracking
        self._record_source(password, source_url)
        return ValidationResult(password, False, reason, source_url, confidence="rejected")

    def summary(self) -> dict:
        return {
            "accepted_count": len(self.accepted_passwords),
            "accepted_passwords": sorted(self.accepted_passwords),
            "source_map": {pw: urls for pw, urls in self.seen_sources.items()
                           if pw in self.accepted_passwords},
        }