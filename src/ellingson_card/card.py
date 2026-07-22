"""Load and validate A2A v1.0 Agent Cards.

Field names follow the A2A v1.0.0 spec (verified 2026-06-22): the well-known
served JSON uses OpenAPI-style ``securitySchemes`` and an ``supportedInterfaces``
array whose entries carry ``protocolVersion``. Validation is intentionally
structural and operates on the served JSON bytes so that what is signed is
exactly what is served.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REQUIRED_TOP_LEVEL = (
    "name",
    "description",
    "version",
    "supportedInterfaces",
    "securitySchemes",
    "skills",
)


class CardError(ValueError):
    """Raised when an Agent Card is missing required fields or is malformed."""


def read_card(path: Path) -> dict[str, Any]:
    """Read and parse an Agent Card JSON file into a dict.

    The single read/parse entry point shared by the sign and verify paths, so
    both emit identical, failure-mode-distinguished errors.

    Args:
        path: Path to the Agent Card JSON file.

    Returns:
        The parsed card as a dict (the served JSON, unmodified).

    Raises:
        CardError: If the file cannot be read, is not valid JSON, or does not
            decode to a JSON object.
    """
    try:
        card = json.loads(path.read_text())
    except OSError as exc:
        raise CardError(f"cannot read card {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CardError(f"invalid card JSON {path}: {exc}") from exc
    if not isinstance(card, dict):
        raise CardError(f"card must be a JSON object, got {type(card).__name__}")
    return card


def _is_empty(value: Any) -> bool:
    if isinstance(value, str):
        return not value.strip()
    return not value


def _check_required_fields(card: dict[str, Any]) -> None:
    missing = [field for field in _REQUIRED_TOP_LEVEL if field not in card]
    empty = [field for field in _REQUIRED_TOP_LEVEL if field in card and _is_empty(card[field])]
    problems = []
    if missing:
        problems.append(f"card missing required field(s): {', '.join(missing)}")
    if empty:
        problems.append(f"card required field(s) present but empty: {', '.join(empty)}")
    if problems:
        raise CardError("; ".join(problems))


def load_card(path: Path) -> dict[str, Any]:
    """Read an Agent Card and validate the fields the pipeline relies on.

    Args:
        path: Path to the Agent Card JSON file.

    Returns:
        The parsed card as a dict (the served JSON, unmodified).

    Raises:
        CardError: If the card cannot be read, a required field is absent or
            empty (whitespace-only strings count as empty), an interface entry
            is not an object, an interface url is not
            a string, or an interface declares a non-HTTPS endpoint.
    """
    card = read_card(path)
    _check_required_fields(card)

    interfaces = card["supportedInterfaces"]
    if not isinstance(interfaces, list) or not interfaces:
        raise CardError("supportedInterfaces must be a non-empty array")
    for iface in interfaces:
        if not isinstance(iface, dict):
            raise CardError(f"interface entry must be an object, got {type(iface).__name__}")
        url = iface.get("url", "")
        if not isinstance(url, str):
            raise CardError(f"interface url must be a string, got {type(url).__name__}")
        if not url.startswith("https://"):
            raise CardError(f"interface endpoint must be HTTPS, got: {url!r}")

    return card


def card_for_signing(card: dict[str, Any]) -> dict[str, Any]:
    """Return the signing view of a card: a copy with ``signatures`` removed.

    The A2A v1.0 spec requires the JCS canonical form used for signing to exclude
    the ``signatures`` field so the card can be reconstructed during verification.
    """
    return {key: value for key, value in card.items() if key != "signatures"}
