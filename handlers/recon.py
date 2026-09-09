"""
handlers/recon.py — /recon <domain>: runs the full passive recon pipeline
in one command instead of five separate ones.

This is genuinely just automation, not a new capability: it calls the
exact same get_*_text() functions that /whois, /dns, /subdomains,
/headers, and /audit already use individually (defined in osint.py and
security.py) — nothing here re-implements any lookup logic. Each section
is sent as its own message so results show up progressively instead of
one long wait, and one slow/failing section can't block the others
(each get_*_text() already catches its own errors and returns a message
string instead of raising).
"""

from core import bot
from formatting import safe_reply
from .osint import get_whois_text, get_dns_text, get_subdomains_text, get_headers_text
from .security import get_audit_text


@bot.message_handler(commands=["recon"])
def recon_cmd(message):
    domain = message.text.replace("/recon", "", 1).strip()
    if not domain:
        bot.reply_to(
            message,
            "Usage: /recon <domain>\ne.g. /recon example.com\n\n"
            "Runs WHOIS, DNS, subdomain enumeration, headers, and a security "
            "audit in one go — the same checks as /whois, /dns, /subdomains, "
            "/headers, and /audit individually, just automated.\n\n"
            "⚠️ Use only on targets you own or have explicit permission to test.",
        )
        return

    bot.reply_to(message, f"🔎 Starting recon on *{domain}*...", parse_mode="Markdown")

    steps = [
        ("📄 WHOIS", lambda: get_whois_text(domain)),
        ("🌐 DNS Records", lambda: get_dns_text(domain)),
        ("🔎 Subdomains", lambda: get_subdomains_text(domain)),
        ("📡 Headers", lambda: get_headers_text(domain)),
        ("🛡 Security Audit", lambda: get_audit_text(domain)),
    ]

    for label, step_func in steps:
        bot.send_chat_action(message.chat.id, "typing")
        try:
            result = step_func()
        except Exception as e:
            result = f"⚠️ {label} step failed unexpectedly: {e}"
        safe_reply(message, result)

    bot.send_message(message.chat.id, f"✅ Recon complete for *{domain}*", parse_mode="Markdown")
