"""
handlers/webtools.py — /jwt and /encode: web-app testing utilities, the
kind found in Burp Suite's Decoder or jwt.io. Pure data transformation —
no network requests, no target interaction.
"""

import base64
import binascii
import html
import json
import urllib.parse
from core import bot, DIVIDER
from formatting import safe_reply


def _decode_jwt_part(part: str) -> dict:
    padded = part + "=" * (-len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    return json.loads(decoded)


def get_jwt_text(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "⚠️ That doesn't look like a JWT (expected 3 dot-separated parts: header.payload.signature)."
    try:
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
    except Exception as e:
        return f"⚠️ Failed to decode: {e}"

    warnings = []
    if str(header.get("alg", "")).lower() == "none":
        warnings.append(
            "⚠️ alg=none — this token claims no signature is needed. If the "
            "server actually honors that, it's a classic auth-bypass bug."
        )

    reply = (
        "🔑 *JWT Decoded*\n" + DIVIDER + "\n\n"
        f"*Header:*\n```json\n{json.dumps(header, indent=2)}\n```\n"
        f"*Payload:*\n```json\n{json.dumps(payload, indent=2)}\n```\n"
        "_Signature not verified — this only decodes, it doesn't check validity._"
    )
    if warnings:
        reply += "\n\n" + "\n".join(warnings)
    return reply


@bot.message_handler(commands=["jwt"])
def jwt_cmd(message):
    token = message.text.replace("/jwt", "", 1).strip()
    if not token:
        bot.reply_to(
            message,
            "Usage: /jwt <token>\n"
            "e.g. /jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123",
        )
        return
    safe_reply(message, get_jwt_text(token))


ENCODE_FORMATS = ("url", "html", "hex")


def encode_decode(fmt: str, mode: str, text: str) -> str:
    fmt, mode = fmt.lower(), mode.lower()
    if fmt == "url":
        return urllib.parse.quote(text) if mode == "encode" else urllib.parse.unquote(text)
    if fmt == "html":
        return html.escape(text) if mode == "encode" else html.unescape(text)
    if fmt == "hex":
        if mode == "encode":
            return text.encode().hex()
        return bytes.fromhex(text).decode(errors="replace")
    raise ValueError(f"Unknown format '{fmt}'. Supported: {', '.join(ENCODE_FORMATS)}")


@bot.message_handler(commands=["encode"])
def encode_cmd(message):
    parts = message.text.split(maxsplit=3)
    if (
        len(parts) < 4
        or parts[1].lower() not in ENCODE_FORMATS
        or parts[2].lower() not in ("encode", "decode")
    ):
        bot.reply_to(
            message,
            "Usage: /encode <url|html|hex> <encode|decode> <text>\n"
            "e.g. /encode url encode hello world\n"
            "e.g. /encode hex decode 68656c6c6f",
        )
        return
    fmt, mode, text = parts[1], parts[2], parts[3]
    try:
        result = encode_decode(fmt, mode, text)
        safe_reply(message, f"```\n{result}\n```")
    except (ValueError, binascii.Error) as e:
        bot.reply_to(message, f"⚠️ {mode.capitalize()} failed: {e}")
