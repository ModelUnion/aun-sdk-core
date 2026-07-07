from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
import uuid

from .aid import AID
from .result import Result, result_err, result_ok
from .v2.crypto.canonical import canonical_json as _canonical_json_bytes

GROUP_INDEX_SCHEMA = "aun.group.index.v1"
GROUP_INDEX_KEY = "group.index"
GROUP_INDEX_SIG_ALG = "ECDSA-P256-SHA256"


class GroupIndexMetaCache:
    def __init__(self, aun_path: str | os.PathLike[str] | None = None) -> None:
        self._aun_path = Path(aun_path) if aun_path else None
        self._remote: dict[tuple[str, str], dict[str, Any]] = {}
        self._local_etags: dict[tuple[str, str], str] = {}
        self._stale: set[tuple[str, str]] = set()
        self._settings: dict[tuple[str, str], dict[str, Any]] = {}
        self._entry_etags: dict[tuple[str, str], dict[str, str]] = {}

    def observe_rpc_meta(self, meta: dict[str, Any], *, local_aid: str) -> None:
        group_indexes = meta.get("group_indexes") if isinstance(meta, dict) else None
        if not isinstance(group_indexes, dict):
            return
        local = str(local_aid or "")
        for group_aid, value in group_indexes.items():
            if not isinstance(value, dict):
                continue
            key = (local, str(group_aid))
            remote = {
                name: value.get(name)
                for name in ("etag", "last_modified", "schema")
                if value.get(name) is not None
            }
            self._load_key(key)
            self._remote[key] = remote
            remote_etag = str(remote.get("etag") or "")
            if remote_etag and self._local_etags.get(key) != remote_etag:
                self._stale.add(key)
            self._save_key(key)

    def mark_fresh(self, local_aid: str, group_aid: str, *, etag: str) -> None:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        self._local_etags[key] = str(etag or "")
        self._stale.discard(key)
        self._save_key(key)

    def is_stale(self, local_aid: str, group_aid: str) -> bool:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        return key in self._stale

    def remote_meta(self, local_aid: str, group_aid: str) -> dict[str, Any] | None:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        value = self._remote.get(key)
        return dict(value) if value else None

    def local_etag(self, local_aid: str, group_aid: str) -> str:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        return self._local_etags.get(key, "")

    def cached_settings(self, local_aid: str, group_aid: str, keys: list[str]) -> dict[str, Any] | None:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        settings = self._settings.get(key) or {}
        if any(item not in settings for item in keys):
            return None
        return {item: settings[item] for item in keys}

    def cached_settings_by_entries(
        self,
        local_aid: str,
        group_aid: str,
        keys: list[str],
        entries: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[str]]:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        settings = self._settings.get(key) or {}
        local_entry_etags = self._entry_etags.get(key) or {}
        remote_entry_etags = {str(item.get("key") or ""): str(item.get("etag") or "") for item in entries}
        cached: dict[str, Any] = {}
        missing: list[str] = []
        for item in keys:
            if item in settings and local_entry_etags.get(item) == remote_entry_etags.get(item):
                cached[item] = settings[item]
            else:
                missing.append(item)
        return cached, missing

    def cache_settings(
        self,
        local_aid: str,
        group_aid: str,
        settings: dict[str, Any],
        *,
        entries: list[dict[str, Any]] | None = None,
        etag: str = "",
        group_index: str | dict[str, Any] | None = None,
    ) -> None:
        key = (str(local_aid or ""), str(group_aid or ""))
        self._load_key(key)
        current = dict(self._settings.get(key) or {})
        current.update(settings)
        self._settings[key] = current
        if entries is not None:
            entry_etags = dict(self._entry_etags.get(key) or {})
            for item in entries:
                entry_key = str(item.get("key") or "")
                if entry_key:
                    entry_etags[entry_key] = str(item.get("etag") or "")
            self._entry_etags[key] = entry_etags
        if etag:
            self.mark_fresh(local_aid, group_aid, etag=etag)
        else:
            self._save_key(key)
        self._save_group_index_body(key, group_index)

    def _dir_for_key(self, key: tuple[str, str]) -> Path | None:
        if self._aun_path is None:
            return None
        local_aid, group_aid = key
        if not local_aid or not group_aid:
            return None
        for value in key:
            if "/" in value or "\\" in value or "\0" in value:
                raise ValueError("group index cache aid must not contain path separators")
        return self._aun_path / "AIDs" / local_aid / "groups" / group_aid

    def _cache_path_for_key(self, key: tuple[str, str]) -> Path | None:
        cache_dir = self._dir_for_key(key)
        return cache_dir / "group-index-cache.json" if cache_dir is not None else None

    def _index_path_for_key(self, key: tuple[str, str]) -> Path | None:
        cache_dir = self._dir_for_key(key)
        return cache_dir / "index.jsonl" if cache_dir is not None else None

    def _load_key(self, key: tuple[str, str]) -> None:
        if key in self._settings or key in self._local_etags or key in self._remote:
            return
        path = self._cache_path_for_key(key)
        if path is None or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if isinstance(data.get("remote_meta"), dict):
            self._remote[key] = dict(data["remote_meta"])
        local_etag = str(data.get("local_etag") or "")
        if local_etag:
            self._local_etags[key] = local_etag
        if isinstance(data.get("settings"), dict):
            self._settings[key] = dict(data["settings"])
        if isinstance(data.get("entry_etags"), dict):
            self._entry_etags[key] = {str(k): str(v) for k, v in data["entry_etags"].items()}
        remote_etag = str((self._remote.get(key) or {}).get("etag") or "")
        if remote_etag and self._local_etags.get(key) != remote_etag:
            self._stale.add(key)

    def _save_key(self, key: tuple[str, str]) -> None:
        path = self._cache_path_for_key(key)
        if path is None:
            return
        payload = {
            "local_aid": key[0],
            "group_aid": key[1],
            "remote_meta": self._remote.get(key) or {},
            "local_etag": self._local_etags.get(key, ""),
            "settings": self._settings.get(key) or {},
            "entry_etags": self._entry_etags.get(key) or {},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def _save_group_index_body(self, key: tuple[str, str], group_index: str | dict[str, Any] | None) -> None:
        if group_index is None:
            return
        body = group_index.get("body") if isinstance(group_index, dict) else group_index
        text = str(body or "")
        if not text:
            return
        path = self._index_path_for_key(key)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        os.replace(tmp, path)


def _canonical_json(value: Any) -> str:
    return _canonical_json_bytes(value).decode("utf-8")


def _canonical_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(item) for item in entries]
    return sorted(normalized, key=lambda item: str(item.get("key") or ""))


def _entries_bytes(entries: list[dict[str, Any]]) -> bytes:
    lines = [_canonical_json(item) for item in _canonical_entries(entries)]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def compute_group_index_body_hash(entries: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(_entries_bytes(entries)).hexdigest()


def group_index_etag(entries: list[dict[str, Any]]) -> str:
    return '"sha256:' + hashlib.sha256(_entries_bytes(entries)).hexdigest() + '"'


def group_index_signing_payload(meta: dict[str, Any], entries: list[dict[str, Any]]) -> bytes:
    meta_without_signature = dict(meta)
    meta_without_signature.pop("signature", None)
    lines = [_canonical_json(meta_without_signature)]
    lines.extend(_canonical_json(item) for item in _canonical_entries(entries))
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_signed_group_index(
    *,
    group_aid: str,
    entries: list[dict[str, Any]],
    signer: AID,
    last_modified: int,
    schema: str = GROUP_INDEX_SCHEMA,
) -> dict[str, Any]:
    canonical_entries = _canonical_entries(entries)
    meta = {
        "type": "index_meta",
        "group_aid": str(group_aid),
        "etag": group_index_etag(canonical_entries),
        "last_modified": int(last_modified),
        "schema": str(schema),
        "body_hash": compute_group_index_body_hash(canonical_entries),
        "signed_by": signer.aid,
        "sig_alg": GROUP_INDEX_SIG_ALG,
    }
    signed = signer.sign(group_index_signing_payload(meta, canonical_entries))
    if not signed.ok:
        raise ValueError(signed.message or "group index signing failed")
    meta["signature"] = signed.data["signature"]
    body_lines = [_canonical_json(meta)]
    body_lines.extend(_canonical_json(item) for item in canonical_entries)
    body = "\n".join(body_lines) + "\n"
    return {"body": body, "meta": meta, "entries": canonical_entries}


def parse_group_index(body: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(body, dict):
        body = str(body.get("body") or "")
    lines = [line for line in str(body or "").splitlines() if line.strip()]
    if not lines:
        raise ValueError("group index body is empty")
    meta = json.loads(lines[0])
    entries = [json.loads(line) for line in lines[1:]]
    if meta.get("type") != "index_meta":
        raise ValueError("first group index line must be index_meta")
    return {"meta": meta, "entries": entries}


def verify_group_index(body: str | dict[str, Any], signer: AID) -> Result[dict[str, Any]]:
    try:
        parsed = parse_group_index(body)
        meta = parsed["meta"]
        entries = parsed["entries"]
        signature = str(meta.get("signature") or "")
        if not signature:
            return result_ok({"valid": False, "reason": "signature missing"})
        if str(meta.get("signed_by") or "") != signer.aid:
            return result_ok({"valid": False, "reason": "signed_by mismatch"})
        if str(meta.get("sig_alg") or "") != GROUP_INDEX_SIG_ALG:
            return result_ok({"valid": False, "reason": "unsupported sig_alg"})
        expected_hash = compute_group_index_body_hash(entries)
        if str(meta.get("body_hash") or "") != expected_hash:
            return result_ok({"valid": False, "reason": "body_hash mismatch"})
        expected_etag = group_index_etag(entries)
        if str(meta.get("etag") or "") != expected_etag:
            return result_ok({"valid": False, "reason": "etag mismatch"})
        verified = signer.verify(group_index_signing_payload(meta, entries), signature)
        if not verified.ok:
            return result_err(verified.code, verified.message or "group index verify failed")
        if not bool(verified.data.get("valid")):
            return result_ok({"valid": False, "reason": "signature verification failed"})
        return result_ok({"valid": True, "meta": meta, "entries": _canonical_entries(entries)})
    except Exception as exc:
        return result_err("GROUP_INDEX_VERIFY_ERROR", str(exc), cause=exc)


def _setting_entry(key: str, value: Any, last_modified: int) -> dict[str, Any]:
    value_bytes = _canonical_json(value).encode("utf-8")
    digest = hashlib.sha256(value_bytes).hexdigest()
    return {
        "key": key,
        "source": "db",
        "etag": f'"sha256:{digest}"',
        "last_modified": int(last_modified),
    }


def prepare_group_settings_with_index(
    *,
    group_aid: str,
    settings: dict[str, Any],
    signer: AID,
    last_modified: int,
    base_index: str | dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = dict(settings)
    updated_entries = [
        _setting_entry(key, value, last_modified)
        for key, value in settings.items()
        if key != GROUP_INDEX_KEY
    ]
    updated_keys = {str(item.get("key") or "") for item in updated_entries}
    entries: list[dict[str, Any]] = []
    if base_index:
        parsed = parse_group_index(base_index)
        entries.extend(
            dict(item)
            for item in parsed["entries"]
            if str(item.get("key") or "") not in updated_keys
        )
    entries.extend(updated_entries)
    result[GROUP_INDEX_KEY] = build_signed_group_index(
        group_aid=group_aid,
        entries=entries,
        signer=signer,
        last_modified=last_modified,
    )
    return result
