"""Regenerate with uv run --no-project --with standardwebhooks==1.3.0 python."""
import json
from datetime import datetime, timezone
from pathlib import Path

from standardwebhooks.webhooks import Webhook

now = datetime.fromtimestamp(1614265330, timezone.utc)
body = '{"id":"msg_fixture"}'
current = Webhook(bytes(range(32, 64)))
previous = Webhook(bytes(range(32)))
result = {
    "body": body,
    "current": current.sign("msg_fixture", now, body),
    "previous": previous.sign("msg_fixture", now, body),
    "array": current.sign("msg_fixture", now, "[]"),
}
Path(__file__).with_name("webhook-vectors.json").write_text(
    json.dumps(result, indent=2) + "\n", encoding="utf-8"
)
