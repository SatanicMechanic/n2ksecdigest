"""HTML and plain-text rendering for the digest email.

All LLM-supplied content is HTML-escaped before interpolation.
Item URLs are validated to be http/https before use as anchor targets —
anything else renders as "#" to neutralize javascript:/data:/file: payloads.
"""

import html
from urllib.parse import urlsplit


_CATEGORY_LABEL = {
    "threat":     "🔴 Threat",
    "tooling":    "🔧 Tooling Update",
    "compliance": "📋 Compliance/Policy",
}

_SEVERITY_LABEL = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
}

_SEVERITY_BORDER = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
}


def _safe_url(url: str) -> str:
    """Return the URL only if it is http(s); otherwise '#'."""
    if not url:
        return "#"
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return "#"
    if scheme not in ("http", "https"):
        return "#"
    return url


def _esc(s: str) -> str:
    return html.escape(s or "", quote=True)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _item_card(index: int, item: dict) -> str:
    cat = (item.get("category") or "").lower()
    sev = (item.get("severity") or "").lower()
    border = _SEVERITY_BORDER.get(sev, "#475569")
    cat_label = _CATEGORY_LABEL.get(cat, _esc(cat.title()))
    sev_label = _SEVERITY_LABEL.get(sev, _esc(sev.title()))

    headline = _esc(item.get("headline", ""))
    why = _esc(item.get("why", ""))
    action = _esc(item.get("action", ""))
    url = _safe_url(item.get("url", ""))
    link_html = ""
    if url != "#":
        link_html = f"""<a href="{_esc(url)}"
                 style="font-size:12px; font-family:monospace; color:#38bdf8;
                        text-decoration:none;">
                Read more →
              </a>"""

    return f"""
    <tr>
      <td style="padding: 0 0 18px 0;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:#1e293b; border-radius:8px;
                      border-left:4px solid {border};">
          <tr>
            <td style="padding:20px 24px;">

              <p style="margin:0 0 10px 0; font-size:11px; font-family:monospace;
                         text-transform:uppercase; letter-spacing:0.08em; color:#64748b;">
                {index}&nbsp;&nbsp;·&nbsp;&nbsp;{cat_label}&nbsp;&nbsp;·&nbsp;&nbsp;{sev_label}
              </p>

              <p style="margin:0 0 14px 0; font-size:16px; font-weight:700;
                         color:#f1f5f9; line-height:1.45;">
                {headline}
              </p>

              <p style="margin:0 0 4px 0; font-size:11px; font-family:monospace;
                         text-transform:uppercase; letter-spacing:0.06em; color:#475569;">
                Why it matters
              </p>
              <p style="margin:0 0 12px 0; font-size:13px; color:#94a3b8; line-height:1.65;">
                {why}
              </p>

              <p style="margin:0 0 4px 0; font-size:11px; font-family:monospace;
                         text-transform:uppercase; letter-spacing:0.06em; color:#475569;">
                Action
              </p>
              <p style="margin:0 0 16px 0; font-size:13px; color:#94a3b8; line-height:1.65;">
                {action}
              </p>

              {link_html}

            </td>
          </tr>
        </table>
      </td>
    </tr>"""


def render_html(items: list[dict], date_str: str) -> str:
    cards = "\n".join(_item_card(i, item) for i, item in enumerate(items, 1))
    date_safe = _esc(date_str)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Need to Know — {date_safe}</title>
</head>
<body style="margin:0; padding:0; background:#0f172a;
             font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI',
             Roboto, 'Helvetica Neue', Arial, sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:#0f172a;">
    <tr>
      <td align="center" style="padding:36px 16px;">
        <table width="600" cellpadding="0" cellspacing="0" border="0"
               style="max-width:600px; width:100%;">

          <tr>
            <td style="padding:0 0 28px 0; border-bottom:1px solid #1e293b;">
              <p style="margin:0 0 6px 0; font-size:11px; font-family:monospace;
                         text-transform:uppercase; letter-spacing:0.12em; color:#475569;">
                Need to Know
              </p>
              <p style="margin:0; font-size:24px; font-weight:700; color:#f1f5f9;">
                🛡️&nbsp; {date_safe}
              </p>
            </td>
          </tr>

          <tr><td style="padding-top:22px;"></td></tr>

          {cards}

          <tr>
            <td style="padding:12px 0 0 0; border-top:1px solid #1e293b;">
              <p style="margin:16px 0 0 0; font-size:11px; color:#334155;
                         text-align:center; font-family:monospace;">
                Generated automatically from public security and platform feeds.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------

def render_text(items: list[dict], date_str: str) -> str:
    """Plain-text fallback. Resend takes both html and text bodies."""
    out = [
        f"NEED TO KNOW — {date_str}",
        "=" * 60,
        "",
    ]
    for i, item in enumerate(items, 1):
        cat = (item.get("category") or "").upper()
        sev = (item.get("severity") or "").upper()
        out.append(f"{i}. [{cat} / {sev}] {item.get('headline','')}")
        out.append("")
        out.append(f"   Why: {item.get('why','')}")
        out.append(f"   Action: {item.get('action','')}")
        url = _safe_url(item.get("url", ""))
        if url != "#":
            out.append(f"   Link: {url}")
        out.append("")
    out.append("-" * 60)
    out.append("Generated automatically from public security and platform feeds.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Subject line
# ---------------------------------------------------------------------------

def subject_line(items: list[dict], date_str: str) -> str:
    """Prefix a severity indicator so Critical/High digests sort visually."""
    severities = {(i.get("severity") or "").lower() for i in items}
    if "critical" in severities:
        prefix = "🛡️🔴"
    elif "high" in severities:
        prefix = "🛡️🟠"
    else:
        prefix = "🛡️"
    n = len(items)
    suffix = f"({n} item{'s' if n != 1 else ''})"
    return f"{prefix} Need to Know — {date_str} {suffix}"
