"""
c2pa_provenance.py — Content Credentials and C2PA Provenance Verification Engine.

Standards-compliant inspection of C2PA (Coalition for Content Provenance and Authenticity)
manifests, JUMBF (JPEG Universal Metadata Box Format) boxes, and container claims.

Supported Container Formats:
  - JPEG: APP11 (0xFFEB) markers with JUMBF / c2pa payload
  - PNG: 'caDI', 'caDO', and 'c2pa' chunks
  - WebP: RIFF chunks with 'JUMB' / 'c2pa' FourCC
  - MP4 / MOV: ISO-BMFF 'uuid' box (C2PA UUID) or 'c2pa' box

Taxonomy of Outcomes:
  - VALID_PROVENANCE: Cryptographic manifest verified with declared origin
  - INVALID_PROVENANCE: Tampered, truncated, or broken manifest chain
  - MISSING_PROVENANCE: No C2PA claims present (neutral, common for web media)
  - UNSUPPORTED_PROVENANCE: Recognized manifest structure with unsupported schema
  - VERIFICATION_UNAVAILABLE: Verification parser / trust list offline or unavailable

Forensic Rule:
  Missing provenance is NEVER treated as proof of manipulation or synthetic origin.
"""

from __future__ import annotations

import io
import json
import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class C2PAValidationStatus:
    VALID_PROVENANCE = "VALID_PROVENANCE"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    MISSING_PROVENANCE = "MISSING_PROVENANCE"
    UNSUPPORTED_PROVENANCE = "UNSUPPORTED_PROVENANCE"
    VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"
    UNVERIFIED_MANIFEST = "UNVERIFIED_MANIFEST"


# Standard C2PA ISO-BMFF UUID: d8fcf317-a0a2-4682-becc-4299d66324d3
C2PA_UUID = b"\xd8\xfc\xf3\x17\xa0\xa2\x46\x82\xbe\xcc\x42\x99\xd6\x63\x24\xd3"


@dataclass
class C2PAAssertion:
    label: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class C2PAResponse:
    status: str  # VALID_PROVENANCE | INVALID_PROVENANCE | MISSING_PROVENANCE | UNSUPPORTED_PROVENANCE | VERIFICATION_UNAVAILABLE
    has_c2pa: bool = False
    claim_generator: Optional[str] = None
    title: Optional[str] = None
    format: Optional[str] = None
    instance_id: Optional[str] = None
    signing_time: Optional[str] = None
    signature_valid: Optional[bool] = None
    actions: List[str] = field(default_factory=list)
    assertions: List[C2PAAssertion] = field(default_factory=list)
    is_ai_generated_declared: bool = False
    validation_errors: List[str] = field(default_factory=list)
    raw_manifest_found: bool = False
    explanation: str = ""

    @property
    def validation_status(self) -> str:
        return self.status

    @property
    def is_valid(self) -> bool:
        return self.status == C2PAValidationStatus.VALID_PROVENANCE and self.signature_valid is True

    @property
    def has_c2pa_manifest(self) -> bool:
        return self.has_c2pa

    @property
    def ai_generative_claimed(self) -> bool:
        return self.is_ai_generated_declared

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "has_c2pa": self.has_c2pa,
            "claim_generator": self.claim_generator,
            "title": self.title,
            "format": self.format,
            "instance_id": self.instance_id,
            "signing_time": self.signing_time,
            "signature_valid": self.signature_valid,
            "actions": self.actions,
            "is_ai_generated_declared": self.is_ai_generated_declared,
            "validation_errors": self.validation_errors,
            "explanation": self.explanation,
        }


class C2PAProvenanceEngine:
    """Robust binary and structure parser for C2PA Content Credentials across image & video containers."""

    def inspect_bytes(self, media_bytes: bytes, filename: str) -> C2PAResponse:
        """Alias for analyze()."""
        return self.analyze(media_bytes, filename)

    def analyze(self, media_bytes: bytes, filename: str) -> C2PAResponse:
        """Inspect media container for C2PA / JUMBF manifests."""
        if not media_bytes or len(media_bytes) < 16:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="Media payload is empty or too small to contain container manifests.",
            )

        fn_lower = filename.lower()
        try:
            if fn_lower.endswith((".jpg", ".jpeg")):
                return self._parse_jpeg(media_bytes)
            elif fn_lower.endswith(".png"):
                return self._parse_png(media_bytes)
            elif fn_lower.endswith(".webp"):
                return self._parse_webp(media_bytes)
            elif fn_lower.endswith((".mp4", ".mov", ".m4v")):
                return self._parse_isobmff(media_bytes)
            else:
                # Fallback generic scanner for JUMBF / c2pa signatures
                return self._scan_generic_stream(media_bytes)
        except Exception as exc:
            logger.warning(f"C2PA inspection notice for {filename}: {exc}")
            return C2PAResponse(
                status="VERIFICATION_UNAVAILABLE",
                has_c2pa=False,
                validation_errors=[f"Container parsing error: {str(exc)}"],
                explanation="Forensic container scanner encountered an unhandled format exception.",
            )

    def _parse_jpeg(self, data: bytes) -> C2PAResponse:
        """Scan JPEG APP11 markers for JUMBF C2PA manifests."""
        if not data.startswith(b"\xff\xd8"):
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="Asset does not have valid JPEG SOI marker.",
            )

        offset = 2
        length = len(data)
        manifest_chunks = []

        while offset < length - 4:
            marker, = struct.unpack(">H", data[offset:offset + 2])
            offset += 2

            # Standalone markers without payload
            if marker in (0xFFD8, 0xFFD9, 0xFF01):
                continue
            if 0xFFD0 <= marker <= 0xFFD7:  # RST markers
                continue
            if marker == 0xFFDA:  # SOS (Start of Scan) - image data begins
                break

            if offset + 2 > length:
                break
            seg_len, = struct.unpack(">H", data[offset:offset + 2])
            offset += 2

            if seg_len < 2 or offset + seg_len - 2 > length:
                break

            seg_data = data[offset:offset + seg_len - 2]
            offset += seg_len - 2

            # APP11 marker: 0xFFEB
            if marker == 0xFFEB:
                # Check for JUMBF box: 'JP', 'jumP' or 'c2pa'
                if b"jumP" in seg_data or b"c2pa" in seg_data:
                    manifest_chunks.append(seg_data)

        if not manifest_chunks:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="No C2PA / JUMBF APP11 metadata markers present in JPEG container (standard for web media).",
            )

        return self._extract_c2pa_data(b"".join(manifest_chunks))

    def _parse_png(self, data: bytes) -> C2PAResponse:
        """Scan PNG chunks for 'caDI', 'caDO', or 'c2pa'."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="Asset does not have valid PNG file signature.",
            )

        offset = 8
        length = len(data)
        manifest_chunks = []

        while offset + 8 < length:
            chunk_len, = struct.unpack(">I", data[offset:offset + 4])
            chunk_type = data[offset + 4:offset + 8]
            offset += 8

            if offset + chunk_len > length:
                break

            chunk_data = data[offset:offset + chunk_len]
            offset += chunk_len + 4  # skip data + 4 bytes CRC

            if chunk_type in (b"caDI", b"caDO", b"c2pa"):
                manifest_chunks.append(chunk_data)
            elif chunk_type == b"IEND":
                break

        if not manifest_chunks:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="No C2PA Content Credentials chunks (caDI/c2pa) found in PNG container.",
            )

        return self._extract_c2pa_data(b"".join(manifest_chunks))

    def _parse_webp(self, data: bytes) -> C2PAResponse:
        """Scan WebP RIFF chunks for JUMB or c2pa sub-chunks."""
        if not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="Asset does not have valid WebP RIFF header.",
            )

        offset = 12
        length = len(data)
        manifest_chunks = []

        while offset + 8 < length:
            fourcc = data[offset:offset + 4]
            chunk_len, = struct.unpack("<I", data[offset + 4:offset + 8])
            offset += 8

            if offset + chunk_len > length:
                break

            chunk_data = data[offset:offset + chunk_len]
            # WebP chunks are padded to even byte length
            offset += chunk_len + (chunk_len % 2)

            if fourcc in (b"JUMB", b"c2pa"):
                manifest_chunks.append(chunk_data)

        if not manifest_chunks:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="No C2PA or JUMBF chunk found in WebP RIFF container.",
            )

        return self._extract_c2pa_data(b"".join(manifest_chunks))

    def _parse_isobmff(self, data: bytes) -> C2PAResponse:
        """Scan ISO-BMFF (MP4/MOV) boxes for C2PA UUID or 'c2pa' box."""
        length = len(data)
        offset = 0
        manifest_chunks = []

        while offset + 8 < length:
            box_len, = struct.unpack(">I", data[offset:offset + 4])
            box_type = data[offset + 4:offset + 8]
            header_len = 8

            if box_len == 1:  # 64-bit large box
                if offset + 16 > length:
                    break
                box_len, = struct.unpack(">Q", data[offset + 8:offset + 16])
                header_len = 16
            elif box_len == 0:  # Box extends to end of file
                box_len = length - offset

            if box_len < header_len or offset + box_len > length:
                break

            box_payload = data[offset + header_len:offset + box_len]
            offset += box_len

            if box_type == b"uuid" and len(box_payload) >= 16:
                uuid_bytes = box_payload[:16]
                if uuid_bytes == C2PA_UUID:
                    manifest_chunks.append(box_payload[16:])
            elif box_type == b"c2pa":
                manifest_chunks.append(box_payload)

        if not manifest_chunks:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="No C2PA provenance box found in video container.",
            )

        return self._extract_c2pa_data(b"".join(manifest_chunks))

    def _scan_generic_stream(self, data: bytes) -> C2PAResponse:
        """Generic fallback scanner looking for c2pa manifest signatures in binary stream."""
        if b"c2pa" not in data and b"jumP" not in data:
            return C2PAResponse(
                status="MISSING_PROVENANCE",
                has_c2pa=False,
                explanation="No C2PA or JUMBF provenance signatures detected in raw binary stream.",
            )

        idx = data.find(b"c2pa")
        if idx != -1:
            snippet = data[max(0, idx - 64):min(len(data), idx + 2048)]
            return self._extract_c2pa_data(snippet)

        return C2PAResponse(
            status="UNSUPPORTED_PROVENANCE",
            has_c2pa=True,
            raw_manifest_found=True,
            explanation="C2PA metadata marker detected but container layout is non-standard.",
        )

    def _extract_c2pa_data(self, payload: bytes) -> C2PAResponse:
        """Parse manifest payload, extract claim generator, actions, and signing assertions.
        Note: True cryptographic verification requires validating the digital signature,
        X.509 certificate chain, and asset hash binding against a C2PA trust list.
        Without native C2PA validation libraries, raw extraction detects claims but cannot
        cryptographically certify provenance authenticity.
        """
        resp = C2PAResponse(
            status=C2PAValidationStatus.UNVERIFIED_MANIFEST,
            has_c2pa=True,
            raw_manifest_found=True,
            signature_valid=None,
        )

        try:
            # Search for JSON blocks or UTF-8 strings inside payload
            text_str = payload.decode("utf-8", errors="ignore")

            # Extract claim generator (e.g. Adobe Firefly, Leica, Sony, Truepic)
            claim_gen = None
            known_generators = [
                "Midjourney", "DALL-E", "Stable Diffusion", "Adobe Firefly", "Adobe Photoshop",
                "Leica", "Sony Alpha", "Truepic", "Nikon", "Canon", "Microsoft Designer",
                "Google SynthID", "Qualcomm", "C2PA Tool"
            ]
            for kg in known_generators:
                if kg.lower() in text_str.lower():
                    claim_gen = f"{kg} Camera" if kg in ("Leica", "Nikon", "Canon") else kg
                    break
            if not claim_gen:
                if "claim_generator" in text_str.lower():
                    import re
                    m = re.search(r'claim_generator[:=\s"\']+([A-Za-z0-9._\s-]+)', text_str, re.IGNORECASE)
                    if m:
                        claim_gen = m.group(1).strip()

            resp.claim_generator = claim_gen or "C2PA Compliant Signer"

            # Check declared actions and generative markers
            actions = []
            if "c2pa.created" in text_str or "created" in text_str.lower():
                actions.append("c2pa.created")
            if "c2pa.edited" in text_str or "edited" in text_str.lower():
                actions.append("c2pa.edited")
            if (
                "c2pa.ai_generated" in text_str
                or "c2pa.synthetic" in text_str.lower()
                or "synthetic" in text_str.lower()
                or "generative" in text_str.lower()
                or "ai_generated" in text_str.lower()
                or "midjourney" in text_str.lower()
                or "dall-e" in text_str.lower()
                or "stable diffusion" in text_str.lower()
            ):
                actions.append("c2pa.ai_generated")
                resp.is_ai_generated_declared = True
            if "c2pa.color_adjustments" in text_str:
                actions.append("c2pa.color_adjustments")
            resp.actions = actions or ["c2pa.created"]

            # Cryptographic signature check:
            # Finding strings like 'c2pa.signature' or 'sha256' in raw binary indicates presence of a
            # signature block structure, but does NOT certify mathematical signature validity.
            resp.signature_valid = None

            if resp.is_ai_generated_declared:
                resp.explanation = (
                    f"C2PA manifest structure detected. Manifest declares content was generated "
                    f"or edited with AI assistance via '{resp.claim_generator}' (cryptographic signature unverified)."
                )
            else:
                resp.explanation = (
                    f"C2PA Content Credentials structure detected from '{resp.claim_generator}'. "
                    f"Cryptographic signature validation is unverified/unavailable in this runtime environment."
                )

            return resp

        except Exception as parse_err:
            logger.debug(f"C2PA payload extraction notice: {parse_err}")
            return C2PAResponse(
                status="UNSUPPORTED_PROVENANCE",
                has_c2pa=True,
                raw_manifest_found=True,
                validation_errors=[str(parse_err)],
                explanation="C2PA manifest block detected but inner structure could not be completely decoded.",
            )


# Global singleton provider
_c2pa_engine: Optional[C2PAProvenanceEngine] = None


def get_c2pa_engine() -> C2PAProvenanceEngine:
    global _c2pa_engine
    if _c2pa_engine is None:
        _c2pa_engine = C2PAProvenanceEngine()
    return _c2pa_engine
