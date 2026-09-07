"""
PyPal — a Telegram coding-helper bot created by ༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻.

Features:
  /start   - welcome + command list
  /menu    - full feature menu with a contact-creator button
  /run     - executes Python code you send and returns the output
  /explain - paste code or an error message, PyPal explains it in plain English
  /tip     - random Python tip
  /ipinfo  - IP/domain geolocation + ISP lookup (OSINT)
  /whois   - domain registration lookup (OSINT)
  /headers - HTTP response headers for a URL (OSINT recon)
  (any other message) - falls back to PyPal directly, so you can just chat
                         about coding problems, bugs, or tracebacks. Asking
                         who made/created the bot returns creator info + a
                         contact button instead of going to the AI.

Cost: €0.
  - pyTelegramBotAPI library: free/open-source
  - Code execution: runs directly on this server, no external API needed
  - Gemini API (AI answers): free tier, no credit card required, generous daily quota

SECURITY NOTE (relevant since you're headed into pentesting!):
  Never hardcode secrets (bot token, API key) directly in this file.
  They're loaded from a separate ".env" file instead. NEVER upload or
  push .env to a public GitHub repo — add it to .gitignore. Only .env.example
  (with blank placeholder values) is safe to share publicly.
"""

import ast
import os
import random
import re
import resource
import subprocess
import requests
import telebot
from telebot import types
from dotenv import load_dotenv

load_dotenv()  # reads the .env file sitting next to this script

BOT_TOKEN = os.environ.get("BOT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN. Check your .env file has BOT_TOKEN=... set.")
if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY. Check your .env file has GEMINI_API_KEY=... set.")

bot = telebot.TeleBot(BOT_TOKEN)

TIPS = [
    "Use list comprehensions for cleaner loops: [x*2 for x in range(10)]",
    "f-strings are the modern, fastest way to format strings: f'{name} is {age}'",
    "Use enumerate() instead of range(len(list)) when you need both index and value.",
    "The 'with' statement auto-closes files for you: with open('f.txt') as f: ...",
    "Use a virtual environment (venv) per project to avoid dependency conflicts.",
    "'is' checks identity, '==' checks equality. Use '==' for comparing values.",
    "Debug fast with print(f'{variable=}') — it prints both name and value.",
    "List slicing: my_list[::-1] reverses a list without a loop.",
    "Use collections.Counter to count items in a list in one line.",
    "Avoid mutable default arguments like def f(x, lst=[]): — it causes bugs.",
]

# --- PyPal's personality and behavior, exactly as designed by Lowkey ---
PYPAL_SYSTEM_PROMPT = """You are PyPal, an expert, patient, and encouraging Python coding tutor and debugger operating inside a Telegram bot. You were created by Lowkey to help beginners master Python without feeling overwhelmed.

YOUR CORE OBJECTIVES:
1. Help users fix Python bugs and understand *why* the error occurred.
2. Explain programming concepts in plain, beginner-friendly terms.
3. Keep code snippets short, well-commented, and mobile-friendly for Telegram screens.

DEBUGGING PROTOCOL:
When a user submits broken code or an error log (Traceback):
1. **Identify the Bug**: State what went wrong in 1-2 simple sentences (e.g., "You have an IndentationError on line 4 because Python requires 4 spaces inside a loop.").
2. **Provide the Fix**: Output the corrected snippet using clear ```python code blocks.
3. **Explain the Principle**: Briefly explain how to avoid this issue in the future. Keep the solution targeted to their code rather than rewriting their entire program from scratch.

TEACHING STYLE & RULES:
- Use clear analogies (e.g., compare variables to labeled boxes, lists to shopping lists).
- If a user asks a broad question (e.g., "How do loops work?"), give a 3-line explanation followed by one simple code example.
- Never mock simple syntax mistakes (missing colons, scope errors, mixing up strings and integers).
- Format all code with proper syntax highlighting using ```python so Telegram renders it cleanly with a copy button.
- Keep responses concise. Most Telegram users read on mobile screens, so avoid walls of text.

TONE:
Supportive, calm, knowledgeable, and practical.

PLATFORM CONSTRAINT: Users can test code themselves via this bot's /run command, which executes single-file Python directly on the server (standard library only — no pip installs). If a fix needs an external package, say so plainly rather than assuming /run can handle it.
"""


def ask_pypal(prompt: str) -> str:
    """Send a prompt to Gemini (free tier) with PyPal's personality and return the reply."""
    model = "gemini-3.5-flash"
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={GEMINI_API_KEY}"
    )
    payload = {
        "system_instruction": {"parts": [{"text": PYPAL_SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": prompt}]}],
    }
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"⚠️ AI request failed: {e}"


FORBIDDEN_MODULES = {
    "os", "subprocess", "sys", "shutil", "socket", "ctypes",
    "importlib", "multiprocessing", "threading", "signal",
    "pty", "resource", "pickle", "marshal", "code", "pdb",
}
FORBIDDEN_NAMES = {"eval", "exec", "__import__", "compile", "open", "globals", "vars"}
FORBIDDEN_ATTRS = {"system", "popen", "remove", "rmdir", "unlink", "kill", "fork"}
MAX_OUTPUT_CHARS = 3000


def is_code_safe(code: str) -> tuple[bool, str]:
    """Static AST check: reject code that imports or calls known-dangerous
    names before it ever runs. Not bulletproof — a determined attacker could
    still build forbidden names dynamically at runtime — but it blocks the
    common, obvious ways sandboxed code escapes to the host system."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FORBIDDEN_MODULES:
                    return False, f"🚫 Importing '{top}' isn't allowed in /run."
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            return False, f"🚫 Using '{node.id}(...)' isn't allowed in /run."
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            return False, f"🚫 Calling '.{node.attr}(...)' isn't allowed in /run."
    return True, ""


def _limit_child_resources():
    """Runs inside the child process, right before it executes user code.
    Caps CPU time, memory, and process count so nothing can hang the
    server, exhaust its RAM, or fork-bomb the container."""
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    mem_bytes = 64 * 1024 * 1024  # 64 MB
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))


def run_python_code(code: str) -> str:
    """Run Python code in a defense-in-depth sandbox (no Docker/VM available
    on this host, so this is layered restrictions, not true isolation):
      1. Static check rejects known-dangerous imports/calls up front.
      2. Runs as a subprocess with a stripped-down environment (no secrets).
      3. CPU time, memory, and process-count limits applied to the child.
      4. Hard timeout as a final backstop.
      5. Output is capped so nothing can flood the chat or the server.
    """
    safe, reason = is_code_safe(code)
    if not safe:
        return reason

    clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

    try:
        result = subprocess.run(
            ["python3", "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env,
            preexec_fn=_limit_child_resources,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            output = (output + "\n" + result.stderr.strip()).strip()
        if not output:
            return "(no output)"
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + "\n... (truncated)"
        return output
    except subprocess.TimeoutExpired:
        return "⚠️ Code timed out (max 10 seconds)."
    except Exception as e:
        return f"⚠️ Execution failed: {e}"


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


AUTHOR_NAME = "༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻"
CONTACT_USERNAME = "Im_just_l0wkey"


@bot.message_handler(commands=["start", "help"])
def start(message):
    contact_markup = types.InlineKeyboardMarkup()
    contact_markup.add(
        types.InlineKeyboardButton(
            text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
        )
    )
    bot.reply_to(
        message,
        f"👋 Hey, I'm *PyPal* — your Python coding buddy, built by {AUTHOR_NAME}.\n\n"
        "*Commands:*\n"
        "/menu — see everything I can do\n"
        "/run `<code>` — run Python code and see the output\n"
        "/explain `<code or error>` — get a plain-English explanation\n"
        "/tip — get a random Python tip\n"
        "/ipinfo, /whois, /headers — basic OSINT lookups (see /menu for details)\n\n"
        "Or just send me your broken code or a traceback directly — no command needed!",
        parse_mode="Markdown",
        reply_markup=contact_markup,
    )


@bot.message_handler(commands=["menu"])
def menu_cmd(message):
    contact_markup = types.InlineKeyboardMarkup()
    contact_markup.add(
        types.InlineKeyboardButton(
            text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
        )
    )
    bot.reply_to(
        message,
        "🐍 *PyPal — Full Menu*\n\n"
        "/run `<code>` — execute Python code on the server and see the output\n\n"
        "/explain `<code or error>` — get a plain-English breakdown of a bug or traceback\n\n"
        "/tip — get a random beginner-friendly Python tip\n\n"
        "*OSINT tools:*\n"
        "/ipinfo `<ip or domain>` — geolocation, ISP, org for an IP\n"
        "/whois `<domain>` — domain registration info\n"
        "/headers `<url>` — HTTP response headers (recon on a site's stack)\n"
        "_Use these only on targets you own or have permission to check._\n\n"
        "*No command needed:* just send broken code, a traceback, or any coding "
        "question directly and PyPal will debug or explain it automatically.\n\n"
        f"Built by {AUTHOR_NAME}",
        parse_mode="Markdown",
        reply_markup=contact_markup,
    )


@bot.message_handler(commands=["run"])
def run_cmd(message):
    code = message.text.replace("/run", "", 1).strip()
    if not code:
        bot.reply_to(message, "Send some code after /run, e.g.:\n/run print(2+2)")
        return
    bot.send_chat_action(message.chat.id, "typing")
    output = run_python_code(code)
    safe_reply(message, f"🖥 Output:\n```\n{output}\n```")


@bot.message_handler(commands=["explain"])
def explain_cmd(message):
    text = message.text.replace("/explain", "", 1).strip()
    if not text:
        bot.reply_to(message, "Send code or an error message after /explain.")
        return
    bot.send_chat_action(message.chat.id, "typing")
    answer = ask_pypal(f"Explain this simply for a Python beginner:\n\n{text}")
    safe_reply(message, answer)


@bot.message_handler(commands=["tip"])
def tip_cmd(message):
    bot.reply_to(message, "💡 " + random.choice(TIPS))


@bot.message_handler(commands=["ipinfo"])
def ipinfo_cmd(message):
    target = message.text.replace("/ipinfo", "", 1).strip()
    if not target:
        bot.reply_to(message, "Usage: /ipinfo <ip or domain>\ne.g. /ipinfo 8.8.8.8")
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        r = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = r.json()
        if data.get("status") != "success":
            safe_reply(message, f"⚠️ Lookup failed: {data.get('message', 'unknown target')}")
            return
        reply = (
            f"🌐 *IP Info: {data.get('query')}*\n"
            f"Country: {data.get('country')} ({data.get('countryCode')})\n"
            f"Region: {data.get('regionName')}\n"
            f"City: {data.get('city')}\n"
            f"ISP: {data.get('isp')}\n"
            f"Org: {data.get('org')}\n"
            f"AS: {data.get('as')}\n"
            f"Timezone: {data.get('timezone')}"
        )
        safe_reply(message, reply)
    except Exception as e:
        bot.reply_to(message, f"⚠️ Lookup failed: {e}")


@bot.message_handler(commands=["whois"])
def whois_cmd(message):
    domain = message.text.replace("/whois", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /whois <domain>\ne.g. /whois example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        import whois as whois_lib
        data = whois_lib.whois(domain)
        fields = [data.registrar, data.creation_date, data.expiration_date, data.name_servers]
        if all(f is None for f in fields):
            # The parser didn't recognize this registry's format (common for
            # some ccTLDs) — fall back to raw text instead of a wall of "None".
            raw = getattr(data, "text", None) or str(data)
            raw = raw.strip()[:MAX_OUTPUT_CHARS] if raw else "No data returned."
            safe_reply(
                message,
                f"📄 *WHOIS: {domain}*\n"
                "(This registry's format isn't fully parsed — showing raw data)\n"
                f"```\n{raw}\n```",
            )
            return
        reply = (
            f"📄 *WHOIS: {domain}*\n"
            f"Registrar: {data.registrar}\n"
            f"Created: {data.creation_date}\n"
            f"Expires: {data.expiration_date}\n"
            f"Name servers: {', '.join(data.name_servers) if data.name_servers else 'N/A'}"
        )
        safe_reply(message, reply)
    except Exception as e:
        bot.reply_to(
            message,
            f"⚠️ WHOIS lookup failed ({e}). Some hosts block outbound WHOIS "
            "(port 43) — this may not work on every server.",
        )


@bot.message_handler(commands=["headers", "header"])
def headers_cmd(message):
    parts = message.text.split(maxsplit=1)
    url = parts[1].strip() if len(parts) > 1 else ""
    if not url:
        bot.reply_to(message, "Usage: /headers <url>\ne.g. /headers https://example.com")
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    bot.send_chat_action(message.chat.id, "typing")
    try:
        r = requests.head(url, timeout=10, allow_redirects=True)
        header_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        reply = f"📡 *Headers for {url}* (status {r.status_code})\n```\n{header_lines}\n```"
        safe_reply(message, reply)
    except Exception as e:
        bot.reply_to(message, f"⚠️ Request failed: {e}")


CREATOR_KEYWORDS = (
    "who made you", "who created you", "who built you", "who developed you",
    "who is your creator", "who's your creator", "your creator", "your author",
    "who owns you", "who is your owner",
)


@bot.message_handler(func=lambda m: True)
def fallback(message):
    """Anything that isn't a known command — broken code, tracebacks, questions —
    goes straight to PyPal, who follows the debugging protocol automatically.
    Questions about the bot's creator are answered directly instead of via AI."""
    text_lower = message.text.lower()
    if any(kw in text_lower for kw in CREATOR_KEYWORDS):
        contact_markup = types.InlineKeyboardMarkup()
        contact_markup.add(
            types.InlineKeyboardButton(
                text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
            )
        )
        bot.reply_to(
            message,
            f"I was built by *{AUTHOR_NAME}* 👨‍💻",
            parse_mode="Markdown",
            reply_markup=contact_markup,
        )
        return
    bot.send_chat_action(message.chat.id, "typing")
    answer = ask_pypal(message.text)
    safe_reply(message, answer)


if __name__ == "__main__":
    print("PyPal is running...")
    bot.infinity_polling()
