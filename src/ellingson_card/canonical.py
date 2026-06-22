"""RFC 8785 (JCS) canonicalization of Agent Cards for signing.

The canonical form excludes the ``signatures`` field per A2A v1.0 §10, so a
verifier can reconstruct the exact bytes that were signed.
"""

from __future__ import annotations

from typing import Any

import rfc8785

from ellingson_card.card import card_for_signing


def canonicalize(card: dict[str, Any]) -> bytes:
    """Return the RFC 8785 JCS canonical bytes of a card's signing view.

    Args:
        card: The Agent Card as served JSON (may include ``signatures``).

    Returns:
        Deterministic, signature-excluded canonical JSON bytes.
    """
    return rfc8785.dumps(card_for_signing(card))
