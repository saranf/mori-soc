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

MANIFEST_NAME = "MANIFEST.json"
CANONICALIZATION = "mori-jcs-v1"   # JSON sort_keys + ensure_ascii=False + UTF-8
HASH_ALGO = "sha256"
SIG_ALGO = "hmac-sha256"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj: Any) -> bytes:
    """캐노니컬 JSON(정렬 키·비ASCII 보존·UTF-8). 같은 내용이면 항상 같은 바이트."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_signed_manifest(
    files: dict[str, bytes], *, generated_at: str, key_id: str = "", secret: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """번들 파일들의 무결성 매니페스트를 만든다(서명 키 있으면 HMAC 서명 포함).

    - files: {파일명: 바이트}. MANIFEST 자신은 제외하고 넣는다.
    - bundle_hash: 파일별 (이름,해시)를 정렬·캐노니컬화한 것의 sha256(번들 전체 지문).
    - secret 있으면 signature(HMAC-SHA256), 없으면 signed=false.
    """
    entries = {name: {"sha256": _sha256(data), "bytes": len(data)}
               for name, data in sorted(files.items())}
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


__all__ = ["MANIFEST_NAME", "build_signed_manifest", "verify_signed_manifest",
           "signing_config_from_env", "write_bundle_with_manifest"]
