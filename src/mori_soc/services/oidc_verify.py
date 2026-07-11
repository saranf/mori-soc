"""GitHub Actions OIDC 토큰(JWT) 검증 — 코드리뷰 증적의 진위성 보장.

정적 공유 토큰은 유출·위조가 가능하고 ``repo`` 도 호출자 자기신고다. GitHub OIDC 는
GitHub 가 서명한 JWT 로 ``repository``·``sha``·``run_id`` 를 **암호학적으로** 증명한다.
MORI 가 이 서명을 검증하면 "이 findings 는 진짜 그 repo 의 그 런에서 나왔다"가 성립한다.

RS256 서명 검증은 **공개키로 공개 데이터를 검증**하는 것이라 (비밀·타이밍 민감성이 없어)
표준 라이브러리만으로 안전하게 구현한다 — 새 의존성을 만들지 않는다(MORI 원칙).
JWKS(공개키)는 호출자가 주입하거나 :func:`fetch_github_jwks` 로 가져온다(테스트 주입 가능).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Callable

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_CONFIG = f"{GITHUB_ISSUER}/.well-known/openid-configuration"
# ASN.1 DigestInfo prefix for SHA-256 (PKCS#1 v1.5)
_SHA256_ASN1 = bytes.fromhex("3031300d060960864801650304020105000420")


class OidcError(Exception):
    """OIDC 검증 실패(서명·클레임 불일치 등)."""


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url_int(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def _rs256_verify(signing_input: bytes, signature: bytes, n: int, e: int) -> bool:
    """PKCS#1 v1.5 SHA-256 서명 검증 (RSA 공개키 (n, e))."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n:
        return False
    em = pow(sig_int, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    t = _SHA256_ASN1 + digest
    ps_len = k - len(t) - 3
    if ps_len < 8:  # 최소 패딩 길이 미달 = 위조
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    return hmac.compare_digest(em, expected)


def verify_github_oidc(
    token: str,
    *,
    audience: str,
    jwks: dict[str, Any],
    allowed_repos: set[str] | None = None,
    allowed_owner: str | None = None,
    now: int,
    leeway: int = 60,
) -> dict[str, Any]:
    """GitHub OIDC JWT 를 검증하고 검증된 클레임을 반환한다. 실패 시 :class:`OidcError`.

    - 서명: JWKS 의 ``kid`` 매칭 공개키로 RS256 검증
    - 클레임: iss(GitHub)·aud(=audience)·exp/nbf(±leeway)
    - 선택: repository allowlist / repository_owner allowlist
    ``now`` 는 epoch 초(호출자가 주입 — 결정적 테스트 위함).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("malformed JWT (segments != 3)")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise OidcError(f"JWT decode failed: {exc}") from exc

    if header.get("alg") != "RS256":
        raise OidcError(f"unsupported alg: {header.get('alg')}")
    kid = header.get("kid")
    key = None
    for k in jwks.get("keys", []) or []:
        if k.get("kid") == kid and k.get("kty") == "RSA":
            key = k
            break
    if key is None:
        raise OidcError(f"no JWKS key for kid={kid}")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if not _rs256_verify(signing_input, signature, _b64url_int(key["n"]), _b64url_int(key["e"])):
        raise OidcError("signature verification failed")

    # ── 클레임 검증 ──
    if claims.get("iss") != GITHUB_ISSUER:
        raise OidcError(f"unexpected iss: {claims.get('iss')}")
    aud = claims.get("aud")
    aud_ok = (aud == audience) or (isinstance(aud, list) and audience in aud)
    if not aud_ok:
        raise OidcError("audience mismatch")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now > exp + leeway:
        raise OidcError("token expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now + leeway < nbf:
        raise OidcError("token not yet valid")

    repo = claims.get("repository")
    if allowed_repos is not None and repo not in allowed_repos:
        raise OidcError(f"repository not allowed: {repo}")
    if allowed_owner and claims.get("repository_owner") != allowed_owner:
        raise OidcError(f"repository_owner not allowed: {claims.get('repository_owner')}")

    return claims


def fetch_github_jwks(config_url: str = GITHUB_OIDC_CONFIG, *, fetch: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    """GitHub OIDC OpenID config → jwks_uri → JWKS 를 가져온다. ``fetch`` 주입 시 테스트용."""
    def _default_fetch(url: str) -> bytes:
        import httpx

        return httpx.get(url, timeout=10.0).content

    _fetch = fetch or _default_fetch
    config = json.loads(_fetch(config_url))
    jwks_uri = config.get("jwks_uri")
    if not jwks_uri:
        raise OidcError("no jwks_uri in OIDC config")
    return json.loads(_fetch(jwks_uri))
