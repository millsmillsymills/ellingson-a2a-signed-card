import base64

from cryptography.hazmat.primitives.asymmetric import ec

from ellingson_card.keys import (
    cert_to_x5c,
    generate_signing_material,
    identity_from_cert,
    x5c_to_cert,
)

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"


def test_generated_key_is_p256_and_identity_round_trips():
    key, cert = generate_signing_material(IDENTITY)
    assert isinstance(key.curve, ec.SECP256R1)
    assert identity_from_cert(cert) == IDENTITY


def test_x5c_round_trips_to_same_cert():
    _, cert = generate_signing_material(IDENTITY)
    x5c = cert_to_x5c(cert)
    assert x5c and base64.b64decode(x5c[0])  # valid base64 DER
    assert identity_from_cert(x5c_to_cert(x5c[0])) == IDENTITY


def test_two_generations_differ():
    key_a, _ = generate_signing_material(IDENTITY)
    key_b, _ = generate_signing_material(IDENTITY)
    a = key_a.private_numbers().private_value
    b = key_b.private_numbers().private_value
    assert a != b
