"""Command-line interface: ``ellingson-card sign|verify|serve``.

Verification failures exit non-zero and print the specific error class name to
stderr, so the shell sees exactly which fail-closed control rejected the card.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from ellingson_card.card import load_card
from ellingson_card.errors import VerificationError
from ellingson_card.keys import generate_signing_material
from ellingson_card.serve import WELL_KNOWN_PATH, make_server
from ellingson_card.signer import attach_signature, sign_card
from ellingson_card.verifier import verify_card


def _cmd_sign(args: argparse.Namespace) -> int:
    card = load_card(args.in_path)
    if args.keyless:
        from ellingson_card.keyless import sign_card_keyless

        signature = sign_card_keyless(card, staging=args.staging)
        detail = "keyless (Sigstore)"
    else:
        key, cert = generate_signing_material(args.identity)
        signature = sign_card(card, key, cert)
        detail = f"ephemeral key, identity: {args.identity}"
    signed = attach_signature(card, signature)
    args.out_path.write_text(json.dumps(signed, indent=2))
    print(f"signed card written to {args.out_path} ({detail})")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    card = json.loads(args.in_path.read_text())
    max_age = timedelta(seconds=args.max_age) if args.max_age is not None else None
    try:
        result = verify_card(
            card,
            expected_identity=args.identity,
            require_rekor=args.require_rekor,
            max_age=max_age,
        )
    except VerificationError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"OK: signature valid; pinned identity {result.identity}")
    print(f"    rekor log index: {result.rekor_log_index}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    server = make_server(args.card_path, args.port)
    print(
        f"serving {args.card_path} at http://127.0.0.1:{server.server_address[1]}{WELL_KNOWN_PATH}"
    )
    server.serve_forever()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ellingson-card")
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign", help="sign an agent card with an ephemeral key")
    sign.add_argument("--in", dest="in_path", type=Path, required=True)
    sign.add_argument("--out", dest="out_path", type=Path, required=True)
    sign.add_argument("--identity", default="https://ellingson-security.example/local-dev")
    sign.add_argument("--keyless", action="store_true", help="sign with Sigstore keyless (CI)")
    sign.add_argument("--staging", action="store_true", help="use the Sigstore staging instance")
    sign.set_defaults(func=_cmd_sign)

    verify = sub.add_parser("verify", help="verify a signed agent card")
    verify.add_argument("--in", dest="in_path", type=Path, required=True)
    verify.add_argument("--identity", required=True)
    verify.add_argument("--no-require-rekor", dest="require_rekor", action="store_false")
    verify.add_argument("--max-age", type=int, default=None, help="max signature age in seconds")
    verify.set_defaults(func=_cmd_verify)

    serve = sub.add_parser("serve", help="serve a signed card at the well-known path")
    serve.add_argument("--card", dest="card_path", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=_cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
