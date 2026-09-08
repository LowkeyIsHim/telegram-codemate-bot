"""
formatting.py — safe_reply(): sends AI-generated or dynamic text using
Telegram MarkdownV2 (which keeps ```code blocks``` and `inline code`
highlighted), while safely escaping everything else so unbalanced
markdown from an AI reply can't crash the send. Falls back to legacy
Markdown, then plain text, if MarkdownV2 parsing still fails for any
reason.

Use this for text you didn't fully control the formatting of (AI
replies, command output). For your own hand-written, known-safe text
(like the /menu message), plain bot.reply_to(..., parse_mode="Markdown")
is simpler and correct — safe_reply's escaping would mangle intentional
markdown you wrote yourself.
"""

import re
from core import bot

_MDV2_SPECIAL = r'_*[]()~`>#+-=|{}.!'


def _escape_mdv2(text: str) -> str:
    """Escape MarkdownV2 special characters in plain (non-code) text."""
    return re.sub(f"([{re.escape(_MDV2_SPECIAL)}])", r"\\\1", text)


def _to_telegram_markdown_v2(text: str) -> str:
    """Convert loose AI-generated markdown into valid Telegram MarkdownV2,
    keeping ```code blocks``` and `inline code` intact so syntax
    highlighting and the copy button still work."""
    parts = re.split(r"(```[\s\S]*?```|`[^`\n]*?`)", text)
    out = []
    for part in parts:
        if part.startswith("```") or (part.startswith("`") and part.endswith("`")):
            out.append(part)  # leave code spans/blocks untouched
        else:
            out.append(_escape_mdv2(part))
    return "".join(out)


def safe_reply(message, text, **kwargs):
    """Reply with rich formatting when possible. Tries MarkdownV2 (which
    keeps code blocks highlighted), then legacy Markdown, then plain text —
    whichever Telegram actually accepts."""
    try:
        bot.reply_to(message, _to_telegram_markdown_v2(text), parse_mode="MarkdownV2", **kwargs)
        return
    except Exception:
        pass
    try:
        bot.reply_to(message, text, parse_mode="Markdown", **kwargs)
        return
    except Exception:
        pass
    bot.reply_to(message, text, **kwargs)
