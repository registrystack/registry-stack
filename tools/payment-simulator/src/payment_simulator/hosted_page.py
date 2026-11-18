"""Server-rendered HTML for the hosted payment page: no JavaScript and no external assets."""

from html import escape
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

BANNER = "Synthetic payment simulator, no real money"
LABELS = {
    "paid": "Paid",
    "failed": "Declined",
    "cancelled": "Cancelled",
    "expired": "Expired",
}
# A strict policy: the page loads nothing and runs nothing. It sets no form-action
# directive because browsers apply that to the redirect that follows a submission.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
)
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:0 auto;padding:1rem}"
    ".banner{background:#fff3cd;border:2px solid #856404;padding:.75rem;font-weight:bold}"
    "dl{display:grid;grid-template-columns:auto 1fr;gap:.25rem 1rem}dt{font-weight:bold}"
    "button{font:inherit;padding:.5rem 1rem;margin:.25rem .25rem .25rem 0}"
)


def amount_text(view):
    scale = view["scale"]
    return f"{view['amount']:.{scale}f} {view['currency']}"


def outcome_url(view):
    """The return URL with the transfer ID and final outcome appended to its query."""
    parts = urlsplit(view["return_url"])
    query = [
        *parse_qsl(parts.query, keep_blank_values=True),
        ("transferRequestId", view["transfer_id"]),
        ("status", view["outcome"]),
    ]
    return urlunsplit(parts._replace(query=urlencode(query)))


def render(view):
    bill = escape(str(view["bill_id"]))
    biller = escape(view["payload"]["billDetails"]["billerName"])
    details = (
        f"<dl><dt>Biller</dt><dd>{biller}</dd><dt>Bill</dt><dd>{bill}</dd>"
        f"<dt>Amount</dt><dd>{escape(amount_text(view))}</dd></dl>"
    )
    if view["final"]:
        label = LABELS[view["outcome"]]
        body = f"<p>Result: <strong>{label}</strong>. This request is final.</p>"
        if view["return_url"]:
            body += f'<p><a href="{escape(outcome_url(view), quote=True)}">Return to the service</a></p>'
    else:
        body = (
            '<form method="post" action="">'
            f'<input type="hidden" name="token" value="{escape(view["form_token"], quote=True)}">'
            '<button type="submit" name="decision" value="pay">Pay</button>'
            '<button type="submit" name="decision" value="decline">Decline</button>'
            '<button type="submit" name="decision" value="cancel">Cancel</button>'
            "</form>"
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="robots" content="noindex">'
        f"<title>{BANNER}</title><style>{STYLE}</style></head><body>"
        f'<p class="banner">{BANNER}</p><h1>Pay a bill</h1>{details}{body}</body></html>'
    )
