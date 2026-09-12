"""Output-handling defenses: HTML escaping and the CSP header value for
the chat UI (aegislab.web.app). See docs/controls/F05_output_handling.md.
"""

from __future__ import annotations

import html

# No 'unsafe-inline' anywhere: inline <script> is blocked by script-src
# 'self' alone, by default -- that absence *is* the "no inline" rule.
CSP_HEADER_VALUE = "default-src 'none'; script-src 'self'"


def escape_for_html(text: str) -> str:
    """HTML-escapes text before it is inserted into a page.

    Model/tool output is DATA, not markup -- this is the fix for the
    vulnerable sink in aegislab.web.app when DEFENSE=off.
    """
    return html.escape(text, quote=True)
