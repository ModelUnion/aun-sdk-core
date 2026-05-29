from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from . import error_codes as codes
from ._cert_utils import (
    build_agent_md_signature_block,
    cert_common_name,
    cert_fingerprint,
    extract_agent_md_aid,
    normalize_agent_md_payload,
    parse_agent_md_tail_signature,
    payload_bytes,
    public_key_der_b64,
    sign_bytes,
    verify_signature,
)
from .result import Result, result_err, result_ok


@dataclass(frozen=True, slots=True)
class AID:
    aid: str
    aun_path: str
    cert_pem: str
    _cert_obj: x509.Certificate
    _private_key_obj: Any | None
    _cert_valid: bool
    _private_key_valid: bool

    @classmethod
    def _create(
        cls,
        *,
        aid: str,
        aun_path: str,
        cert_pem: str,
        cert_obj: x509.Certificate,
        private_key_obj: Any | None,
        cert_valid: bool,
        private_key_valid: bool,
    ) -> "AID":
        return cls(
            aid=str(aid),
            aun_path=str(aun_path),
            cert_pem=str(cert_pem),
            _cert_obj=cert_obj,
            _private_key_obj=private_key_obj,
            _cert_valid=bool(cert_valid),
            _private_key_valid=bool(private_key_valid),
        )

    @property
    def public_key(self) -> str:
        return public_key_der_b64(self._cert_obj)

    @property
    def cert_subject(self) -> str:
        return cert_common_name(self._cert_obj)

    @property
    def cert_not_before(self) -> datetime:
        return self._cert_obj.not_valid_before_utc

    @property
    def cert_not_after(self) -> datetime:
        return self._cert_obj.not_valid_after_utc

    @property
    def cert_issuer(self) -> str:
        return cert_common_name(self._cert_obj, issuer=True)

    @property
    def cert_fingerprint(self) -> str:
        return cert_fingerprint(self._cert_obj)

    def is_cert_valid(self) -> bool:
        return self._cert_valid

    def isCertValid(self) -> bool:
        return self.is_cert_valid()

    def is_private_key_valid(self) -> bool:
        return self._private_key_valid

    def isPrivateKeyValid(self) -> bool:
        return self.is_private_key_valid()

    def sign(self, payload: bytes | str) -> Result[dict[str, str]]:
        if not self.is_private_key_valid() or self._private_key_obj is None:
            return result_err(codes.PRIVATE_KEY_NOT_VALID, "private key is not valid")
        try:
            signature = sign_bytes(self._private_key_obj, payload_bytes(payload))
            return result_ok({"signature": base64.b64encode(signature).decode("ascii")})
        except Exception as exc:
            return result_err(codes.SIGNATURE_OPERATION_ERROR, str(exc), cause=exc)

    def verify(self, payload: bytes | str, signature: str) -> Result[dict[str, bool]]:
        if not self.is_cert_valid():
            return result_err(codes.CERT_NOT_VALID, "certificate is not valid")
        try:
            sig_bytes = base64.b64decode(str(signature or ""), validate=True)
            try:
                verify_signature(self._cert_obj.public_key(), sig_bytes, payload_bytes(payload))
                return result_ok({"valid": True})
            except InvalidSignature:
                return result_ok({"valid": False})
        except Exception as exc:
            return result_err(codes.VERIFICATION_OPERATION_ERROR, str(exc), cause=exc)

    def sign_agent_md(self, content: str) -> Result[dict[str, str]]:
        if not self.is_private_key_valid() or self._private_key_obj is None:
            return result_err(codes.PRIVATE_KEY_NOT_VALID, "private key is not valid")
        try:
            payload = normalize_agent_md_payload(content)
            signature = sign_bytes(self._private_key_obj, payload.encode("utf-8"))
            block = build_agent_md_signature_block(
                cert_fingerprint=self.cert_fingerprint,
                timestamp=int(time.time()),
                signature_b64=base64.b64encode(signature).decode("ascii"),
            )
            return result_ok({"signed": payload + block})
        except Exception as exc:
            return result_err(codes.SIGNATURE_OPERATION_ERROR, str(exc), cause=exc)

    def verify_agent_md(self, content: str) -> Result[dict[str, Any]]:
        if not self.is_cert_valid():
            return result_err(codes.CERT_NOT_VALID, "certificate is not valid")
        try:
            payload, fields, parse_error = parse_agent_md_tail_signature(str(content or ""))
            if fields is None:
                if parse_error is None:
                    return result_ok({"status": "unsigned", "payload": payload})
                return result_ok({"status": "invalid", "payload": payload, "reason": parse_error})

            payload_aid = extract_agent_md_aid(payload)
            if payload_aid and payload_aid != self.aid:
                return result_ok({
                    "status": "invalid",
                    "payload": payload,
                    "aid": payload_aid,
                    "reason": "aid mismatch",
                })
            if fields["cert_fingerprint"].lower() != self.cert_fingerprint.lower():
                return result_ok({
                    "status": "invalid",
                    "payload": payload,
                    "aid": self.aid,
                    "reason": "certificate fingerprint mismatch",
                })

            signature = base64.b64decode(fields["signature"], validate=True)
            try:
                verify_signature(self._cert_obj.public_key(), signature, payload.encode("utf-8"))
            except InvalidSignature:
                return result_ok({
                    "status": "invalid",
                    "payload": payload,
                    "aid": self.aid,
                    "cert_fingerprint": fields["cert_fingerprint"],
                    "timestamp": int(fields["timestamp"]),
                    "reason": "signature verification failed",
                })

            return result_ok({
                "status": "verified",
                "payload": payload,
                "aid": self.aid,
                "cert_fingerprint": fields["cert_fingerprint"],
                "timestamp": int(fields["timestamp"]),
            })
        except Exception as exc:
            return result_err(codes.VERIFICATION_OPERATION_ERROR, str(exc), cause=exc)
