"""
bot.py — entry point only. Imports the handlers package (which registers
every command on the shared bot instance from core.py), then starts polling.

To add a NEW FEATURE, you should almost never need to touch this file:
  - New command in an existing category (e.g. another security tool)?
    → add a function to the matching file in handlers/ (e.g. handlers/security.py)
  - New category entirely?
    → create handlers/<name>.py, add @bot.message_handler(...) functions,
      then add "from . import <name>" to handlers/__init__.py
      (ABOVE the "from . import fallback" line — that one must stay last)

File map:
  core.py           - bot instance, secrets, constants, tips list
  formatting.py     - safe_reply() — Markdown-safe message sending
  ai.py             - PyPal's system prompt + Gemini API call
  sandbox.py        - the /run code-execution sandbox
  handlers/menu.py       - /start, /menu, /tip, menu buttons
  handlers/coding.py     - /run, /explain
  handlers/osint.py      - /ipinfo, /whois, /headers, /subdomains
  handlers/security.py   - /portscan, /cve, /base64
  handlers/fallback.py   - creator-question detection + AI catch-all (loads last)
"""

from core import bot
import handlers  # noqa: F401 — importing this registers all handlers

if __name__ == "__main__":
    print("PyPal is running...")
    bot.infinity_polling()
