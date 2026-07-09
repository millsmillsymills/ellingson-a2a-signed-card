from ellingson_card.canonical import canonicalize


def test_canonicalize_is_deterministic_and_lexicographic():
    card = {"version": "1", "name": "a", "skills": []}
    out = canonicalize(card)
    assert out == canonicalize(card)
    # JCS sorts object keys lexicographically
    assert out.index(b'"name"') < out.index(b'"skills"') < out.index(b'"version"')


def test_canonicalize_excludes_signatures():
    base = {"name": "a", "version": "1"}
    signed = {**base, "signatures": [{"protected": "p", "signature": "s"}]}
    assert canonicalize(base) == canonicalize(signed)


def test_canonicalize_matches_known_jcs():
    # RFC 8785: no whitespace, sorted keys, compact separators.
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
