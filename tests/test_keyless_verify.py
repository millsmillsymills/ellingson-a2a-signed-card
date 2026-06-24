"""Wiring and error-mapping tests for the keyless bundle verify path.

Sigstore's bundle verifier is the external boundary and is mocked here; the real
inclusion-proof round-trip is exercised by the live staging smoke job in CI.
"""

import pytest
import sigstore.models
import sigstore.verify

from ellingson_card.errors import BundleVerificationError
from ellingson_card.keyless_verify import verify_bundle

LEAF_DER = b"\x30\x82leaf-der"
OTHER_DER = b"\x30\x82other-der"
IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"
MESSAGE = b"eyJhbGciOiJFUzI1NiJ9.payload"


class _FakeCert:
    def __init__(self, der):
        self._der = der

    def public_bytes(self, _encoding):
        return self._der


class _FakeInner:
    log_index = 4581700


class _FakeLogEntry:
    _inner = _FakeInner()


class _FakeBundle:
    def __init__(self, der=LEAF_DER):
        self.signing_certificate = _FakeCert(der)
        self.log_entry = _FakeLogEntry()


def _install(monkeypatch, *, bundle=None, from_json=None, verify=None, record=None):
    parse = from_json or (lambda _json: bundle or _FakeBundle())

    class FakeBundleCls:
        from_json = staticmethod(parse)

    class FakeVerifier:
        @classmethod
        def production(cls, *, offline):
            if record is not None:
                record["instance"], record["offline"] = "production", offline
            return cls()

        @classmethod
        def staging(cls, *, offline):
            if record is not None:
                record["instance"], record["offline"] = "staging", offline
            return cls()

        def verify_artifact(self, message, bundle, pinned):
            if record is not None:
                record["message"], record["pinned"] = message, pinned
            if verify is not None:
                verify()

    monkeypatch.setattr(sigstore.models, "Bundle", FakeBundleCls)
    monkeypatch.setattr(sigstore.verify, "Verifier", FakeVerifier)


def test_returns_log_index_on_success(monkeypatch):
    _install(monkeypatch)
    index = verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)
    assert index == 4581700


def test_rejects_cert_not_matching_x5c_leaf(monkeypatch):
    calls = {"verify_artifact": 0}
    _install(
        monkeypatch,
        bundle=_FakeBundle(OTHER_DER),
        verify=lambda: calls.__setitem__("verify_artifact", 1),
    )
    with pytest.raises(BundleVerificationError, match="x5c leaf"):
        verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)
    assert calls["verify_artifact"] == 0


def test_wraps_sigstore_verification_error(monkeypatch):
    from sigstore.errors import VerificationError

    def boom():
        raise VerificationError("inclusion proof does not bind")

    _install(monkeypatch, verify=boom)
    with pytest.raises(BundleVerificationError, match="inclusion proof"):
        verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)


def test_malformed_bundle_fails_closed(monkeypatch):
    def bad_from_json(_json):
        raise ValueError("not a bundle")

    _install(monkeypatch, from_json=bad_from_json)
    with pytest.raises(BundleVerificationError, match="malformed"):
        verify_bundle(MESSAGE, "garbage", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)


def test_staging_selects_staging_trust_root(monkeypatch):
    record = {}
    _install(monkeypatch, record=record)
    verify_bundle(
        MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER, staging=True
    )
    assert record["instance"] == "staging"
    assert record["offline"] is True
    assert record["message"] == MESSAGE


def test_production_is_default(monkeypatch):
    record = {}
    _install(monkeypatch, record=record)
    verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)
    assert record["instance"] == "production"


def test_pins_identity_and_issuer_in_policy(monkeypatch):
    record = {}
    _install(monkeypatch, record=record)
    verify_bundle(
        MESSAGE,
        "{}",
        expected_identity=IDENTITY,
        expected_leaf_der=LEAF_DER,
        expected_issuer="https://token.actions.githubusercontent.com",
    )
    assert record["pinned"]._identity == IDENTITY  # noqa: SLF001 (policy internals)
    assert record["pinned"]._issuer is not None  # noqa: SLF001 (issuer is pinned)


def test_issuer_unset_leaves_policy_issuer_none(monkeypatch):
    record = {}
    _install(monkeypatch, record=record)
    verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)
    assert record["pinned"]._issuer is None  # noqa: SLF001 (no issuer pinned by default)


def test_issuer_mismatch_rejected_on_bundle_path(monkeypatch):
    from sigstore.errors import VerificationError

    def boom():
        raise VerificationError("Certificate's OIDC issuer does not match")

    _install(monkeypatch, verify=boom)
    with pytest.raises(BundleVerificationError, match="OIDC issuer"):
        verify_bundle(
            MESSAGE,
            "{}",
            expected_identity=IDENTITY,
            expected_leaf_der=LEAF_DER,
            expected_issuer="https://token.actions.githubusercontent.com",
        )


def test_non_numeric_log_index_fails_closed(monkeypatch):
    class _BadInner:
        log_index = "not-a-number"

    class _BadEntry:
        _inner = _BadInner()

    class _BadBundle:
        def __init__(self):
            self.signing_certificate = _FakeCert(LEAF_DER)
            self.log_entry = _BadEntry()

    _install(monkeypatch, bundle=_BadBundle())
    with pytest.raises(BundleVerificationError, match="log index"):
        verify_bundle(MESSAGE, "{}", expected_identity=IDENTITY, expected_leaf_der=LEAF_DER)
