"""Signed Evidence Bundle — 내보낸 증적 패키지의 무결성 매니페스트(정리·제품화 C4).

증적 ZIP 을 내보낼 때 각 파일의 sha256 과 번들 해시를 담은 **매니페스트**를 함께 넣는다.
서명 키(MORI_EVIDENCE_SIGNING_KEY)가 있으면 HMAC-SHA256 서명을 붙여 **tamper-evident**
(내보낸 뒤 수정하면 검증 실패)로 만든다. 키가 없으면 정직하게 `signed: false`(해시만).

모리다움 — 과대표현 금지: 이건 tamper-evident 이지 storage-immutable(WORM)이 아니다.
순수 함수 — I/O·환경 접근 없음(키는 호출자가 주입).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from mori_soc.services.hashing import CANONICALIZATION
from mori_soc.services.hashing import sha256_hex as _sha256

# 무결성 매니페스트 파일명 — 번들 콘텐츠의 'manifest.json'(내용)과 대소문자만 다르면 macOS/
# Windows(대소문자 무시)에서 압축 해제 시 충돌·덮어씀. 소문자·비충돌 이름으로 고정(리뷰 #2).
MANIFEST_NAME = "integrity-manifest.json"
HASH_ALGO = "sha256"
SIG_ALGO = "hmac-sha256"


def _canonical(obj: Any) -> bytes:
    """캐노니컬 JSON(compact) — services.hashing 단일 소스에 위임(공통화 C1)."""
    from mori_soc.services.hashing import canonical_json
    return canonical_json(obj, compact=True)


def _manifest_from_entries(
    entries: dict[str, dict[str, Any]], *, generated_at: str, key_id: str = "",
    secret: str = "", extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """이미 계산된 (이름→{sha256,bytes}) 엔트리로 서명 매니페스트를 만든다(원시 바이트 불필요).

    스트리밍 경로(BundleWriter)와 dict 경로(build_signed_manifest)가 공유 — 메모리 절약.
    """
    entries = {name: entries[name] for name in sorted(entries)}
    core: dict[str, Any] = {
        "canonicalization": CANONICALIZATION, "hash_algorithm": HASH_ALGO,
        "generated_at": generated_at, "files": entries,
    }
    if extra:
        core["meta"] = extra
    bundle_hash = _sha256(_canonical(core["files"]))
    core["bundle_hash"] = bundle_hash
    manifest = dict(core)
    if secret:
        signature = hmac.new(secret.encode("utf-8"), _canonical(core), hashlib.sha256).hexdigest()
        manifest["signed"] = True
        manifest["signature_algorithm"] = SIG_ALGO
        manifest["key_id"] = key_id or "default"
        manifest["signature"] = signature
    else:
        manifest["signed"] = False
        manifest["note"] = "서명 키 미설정 — 해시만 포함(tamper-evident 아님). MORI_EVIDENCE_SIGNING_KEY 설정 시 서명."
    return manifest


def build_signed_manifest(
    files: dict[str, bytes], *, generated_at: str, key_id: str = "", secret: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """dict API(작은 번들용): {파일명:바이트} → 서명 매니페스트. 큰 번들은 BundleWriter(스트리밍)."""
    entries = {name: {"sha256": _sha256(data), "bytes": len(data)} for name, data in files.items()}
    return _manifest_from_entries(entries, generated_at=generated_at, key_id=key_id,
                                  secret=secret, extra=extra)


class BundleWriter:
    """ZIP 에 파일을 **스트리밍**하며 무결성 엔트리만 누적(원시 바이트 미보관 → 메모리 절약, M2).

    194개 통제 PDF 를 files dict 로 전부 들고 있던 것을 add() 즉시 write+해시로 바꾼다.
    사용: w=BundleWriter(zf, secret=..); for..: w.add(name, pdf_bytes); w.finalize(generated_at=..).
    """

    def __init__(self, zf: Any, *, secret: str = "", key_id: str = "default") -> None:
        self._zf = zf
        self._secret = secret
        self._key_id = key_id
        self._entries: dict[str, dict[str, Any]] = {}

    def add(self, name: str, data: bytes) -> None:
        if name == MANIFEST_NAME:
            raise ValueError(f"reserved name: {MANIFEST_NAME}")
        self._zf.writestr(name, data)
        self._entries[name] = {"sha256": _sha256(data), "bytes": len(data)}  # 바이트는 여기서 버림

    def finalize(self, *, generated_at: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        manifest = _manifest_from_entries(self._entries, generated_at=generated_at,
                                          key_id=self._key_id, secret=self._secret, extra=extra)
        self._zf.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        return manifest


def verify_signed_manifest(
    manifest: dict[str, Any], files: dict[str, bytes], *, secret: str = "",
) -> dict[str, Any]:
    """매니페스트로 번들 파일 무결성/서명을 검증한다(내보낸 뒤 수정 감지).

    반환: {ok, files_ok, signature_ok, mismatched:[...]}. secret 없거나 미서명 매니페스트면
    signature_ok=None(해시 무결성만 확인).
    """
    entries = manifest.get("files") or {}
    mismatched: list[str] = []
    for name, meta in entries.items():
        data = files.get(name)
        if data is None or _sha256(data) != meta.get("sha256"):
            mismatched.append(name)
    for name in files:
        if name not in entries and name != MANIFEST_NAME:
            mismatched.append(name)   # 매니페스트에 없는 추가 파일도 변조로 본다
    files_ok = not mismatched

    signature_ok: bool | None = None
    if manifest.get("signed") and secret:
        # 서명 대상 core 를 매니페스트에서 재구성(캐노니컬 JSON 은 키 순서 무관).
        signed_keys = ("canonicalization", "hash_algorithm", "generated_at", "files",
                       "meta", "bundle_hash")
        core = {k: manifest[k] for k in signed_keys if k in manifest}
        expected = hmac.new(secret.encode("utf-8"), _canonical(core), hashlib.sha256).hexdigest()
        signature_ok = hmac.compare_digest(expected, str(manifest.get("signature", "")))

    return {"ok": files_ok and (signature_ok is not False),
            "files_ok": files_ok, "signature_ok": signature_ok, "mismatched": mismatched}


def signing_config_from_env() -> tuple[str, str]:
    """서명 키·key_id 를 env 에서 읽는다(라우트 공통 경계). 미설정이면 ('','default') → 미서명."""
    import os
    return (os.getenv("MORI_EVIDENCE_SIGNING_KEY", "").strip(),
            os.getenv("MORI_EVIDENCE_SIGNING_KEY_ID", "default").strip() or "default")


def write_bundle_with_manifest(
    zf: Any, files: dict[str, bytes], *, generated_at: str, secret: str = "",
    key_id: str = "default", extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """ZIP 에 파일들 + 서명 매니페스트(MANIFEST.json)를 쓴다. 모든 증적 ZIP 공통(C4)."""
    for name, data in files.items():
        zf.writestr(name, data)
    manifest = build_signed_manifest(files, generated_at=generated_at, key_id=key_id,
                                     secret=secret, extra=extra)
    zf.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
    return manifest


__all__ = ["MANIFEST_NAME", "BundleWriter", "build_signed_manifest", "verify_signed_manifest",
           "signing_config_from_env", "write_bundle_with_manifest"]
