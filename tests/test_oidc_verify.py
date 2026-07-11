"""GitHub OIDC(JWT/RS256) 검증기 테스트 — 서명·변조·클레임·allowlist.

의존성 없이 테스트 내부에서 RSA 키를 생성해 JWT 를 서명하고, 순수 stdlib 검증기가
정상 통과/위조 거부를 하는지 확인한다(공개키 서명 검증 경로 전체를 실제로 구동).
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import unittest

from mori_soc.services.oidc_verify import GITHUB_ISSUER, OidcError, verify_github_oidc

_ASN1 = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int_b64u(i: int) -> str:
    return _b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))


def _is_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c):
            return c


class _Key:
    def __init__(self, kid: str = "test-kid") -> None:
        random.seed(20260711)  # 결정적
        p, q = _gen_prime(512), _gen_prime(512)
        self.n, self.e, self.d = p * q, 65537, pow(65537, -1, (p - 1) * (q - 1))
        self.kid = kid

    def jwks(self) -> dict:
        return {"keys": [{"kty": "RSA", "kid": self.kid, "n": _int_b64u(self.n), "e": _int_b64u(self.e)}]}

    def sign(self, claims: dict, *, kid: str | None = None, alg: str = "RS256") -> str:
        header = {"alg": alg, "kid": kid or self.kid, "typ": "JWT"}
        h = _b64u(json.dumps(header, separators=(",", ":")).encode())
        p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
        signing = f"{h}.{p}".encode("ascii")
        k = (self.n.bit_length() + 7) // 8
        t = _ASN1 + hashlib.sha256(signing).digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        sig = pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(k, "big")
        return f"{h}.{p}.{_b64u(sig)}"


_KEY = _Key()
_NOW = 1_800_000_000


def _claims(**over) -> dict:
    c = {"iss": GITHUB_ISSUER, "aud": "mori-ingest", "exp": _NOW + 3600, "nbf": _NOW - 60,
         "repository": "acme/webapp", "repository_owner": "acme", "sha": "abc123", "run_id": "42"}
    c.update(over)
    return c


class OidcVerifyTests(unittest.TestCase):
    def test_valid_token_passes_and_returns_claims(self) -> None:
        tok = _KEY.sign(_claims())
        claims = verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)
        self.assertEqual(claims["repository"], "acme/webapp")
        self.assertEqual(claims["sha"], "abc123")

    def test_tampered_payload_fails(self) -> None:
        h, p, s = _KEY.sign(_claims()).split(".")
        forged_payload = _b64u(json.dumps(_claims(repository="attacker/evil"), separators=(",", ":")).encode())
        with self.assertRaises(OidcError):  # 서명이 payload 와 안 맞음
            verify_github_oidc(f"{h}.{forged_payload}.{s}", audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)

    def test_wrong_audience_fails(self) -> None:
        tok = _KEY.sign(_claims(aud="someone-else"))
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)

    def test_expired_fails(self) -> None:
        tok = _KEY.sign(_claims(exp=_NOW - 3600))
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)

    def test_wrong_issuer_fails(self) -> None:
        tok = _KEY.sign(_claims(iss="https://evil.example.com"))
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)

    def test_repo_allowlist_enforced(self) -> None:
        tok = _KEY.sign(_claims(repository="acme/other"))
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(),
                               allowed_repos={"acme/webapp"}, now=_NOW)
        # 허용 목록에 있으면 통과
        ok = _KEY.sign(_claims(repository="acme/webapp"))
        self.assertTrue(verify_github_oidc(ok, audience="mori-ingest", jwks=_KEY.jwks(),
                                           allowed_repos={"acme/webapp"}, now=_NOW))

    def test_unknown_kid_fails(self) -> None:
        tok = _KEY.sign(_claims(), kid="other-kid")
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)

    def test_non_rs256_alg_rejected(self) -> None:
        tok = _KEY.sign(_claims(), alg="none")
        with self.assertRaises(OidcError):
            verify_github_oidc(tok, audience="mori-ingest", jwks=_KEY.jwks(), now=_NOW)


if __name__ == "__main__":
    unittest.main()
