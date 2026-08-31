#!/Users/eduardo/.hermes/personal-admin/.venv/bin/python

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

NTFY_URL = "http://127.0.0.1:2586/personal-admin"

TOKEN_FILE = (
    Path.home()
    / ".hermes"
    / "personal-admin"
    / "ntfy"
    / "publisher_token"
)

PRIORITIES = {
    "remember": "default",
    "important": "high",
    "urgent": "urgent",
}


def fail(message):
    print(
        json.dumps(
            {"ok": False, "error": message},
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )
    sys.exit(1)


def send(args):
    if not TOKEN_FILE.exists():
        fail("ntfy publisher token not found")

    token = TOKEN_FILE.read_text(
        encoding="utf-8"
    ).strip()

    priority = PRIORITIES[args.level]

    request = urllib.request.Request(
        NTFY_URL,
        data=args.message.encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Title": args.title,
            "Priority": priority,
            "Content-Type": "text/plain; charset=utf-8",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        fail(
            f"ntfy HTTP {exc.code}: "
            + exc.read().decode(
                "utf-8",
                errors="replace",
            )
        )

    except Exception as exc:
        fail(f"ntfy delivery failed: {exc}")

    print(
        json.dumps(
            {
                "ok": True,
                "delivered": True,
                "level": args.level,
                "priority": priority,
                "ntfy_id": result.get("id"),
            },
            ensure_ascii=False,
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Private ntfy delivery for Personal Admin"
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    p = sub.add_parser("send")

    p.add_argument(
        "--level",
        choices=[
            "remember",
            "important",
            "urgent",
        ],
        required=True,
    )

    p.add_argument(
        "--title",
        default="Personal Admin",
    )

    p.add_argument(
        "--message",
        required=True,
    )

    p.set_defaults(func=send)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
