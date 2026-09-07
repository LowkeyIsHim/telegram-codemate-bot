"""
PyPal — a Telegram coding-helper bot created by ༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻.

Features:
  /start   - welcome + command list
  /run     - executes Python code you send and returns the output
  /explain - paste code or an error message, PyPal explains it in plain English
  /tip     - random Python tip
  (any other message) - falls back to PyPal directly, so you can just chat
                         about coding problems, bugs, or tracebacks

Cost: €0.
  - pyTelegramBotAPI library: free/open-source
  - Piston API (code execution): free, no signup needed
  - Gemini API (AI answers): free tier, no credit card required, generous daily quota

SECURITY NOTE (relevant since you're headed into pentesting!):
  Never hardcode secrets (bot token, API key) directly in code you might
  commit to GitHub or share. This script reads them from environment
  variables instead. On Replit, set these in the "Secrets" tab (padlock
  icon in the sidebar) — NOT in the code itself, and NOT in the GitHub repo.
"""

import os
import random
import requests
import telebot
from keep_alive import keep_alive

# --- Load secrets from environment variables (set these in Replit "Secrets") ---
BOT_TOKEN = os.environ.get("BOT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN environment variable. Set it in Replit Secrets.")
if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY environment variable. Set it in Replit Secrets.")

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
PYPAL_SYSTEM_PROMPT = """You are PyPal, an expert, patient, and encouraging Python coding tutor and debugger operating inside a Telegram bot. You were created by ༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻ to help beginners master Python without feeling overwhelmed.

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

PLATFORM CONSTRAINT: Users can test code themselves via this bot's /run command, which executes single-file Python using only the standard library (no pip installs, no multi-file projects). If a fix needs an external package, say so plainly rather than assuming /run can handle it.
"""


def ask_pypal(prompt: str) -> str:
    """Send a prompt to Gemini (free tier) with PyPal's personality and return the reply."""
    model = "gemini-2.5-flash"
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


def run_python_code(code: str) -> str:
    """Run Python code remotely (free, no signup) via the Piston API."""
    url = "https://emkc.org/api/v2/piston/execute"
    payload = {
        "language": "python",
        "version": "3.10.0",
        "files": [{"content": code}],
    }
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        result = r.json()
        run_info = result.get("run", {})
        output = run_info.get("output", "").strip()
        return output if output else "(no output)"
    except Exception as e:
        return f"⚠️ Execution failed: {e}"


@bot.message_handler(commands=["start", "help"])
def start(message):
    bot.reply_to(
        message,
        "👋 Hey, I'm *PyPal* — your Python coding buddy, built by ༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻.\n\n"
        "*Commands:*\n"
        "/run `<code>` —> run Python code and see the output\n"
        "/explain `<code or error>` —> get a plain-English explanation\n"
        "/tip —> get a random Python tip\n\n"
        "Or just send me your broken code or a traceback directly — no command needed!",
        parse_mode="Markdown",
    )


@bot.message_handler(commands=["run"])
def run_cmd(message):
    code = message.text.replace("/run", "", 1).strip()
    if not code:
        bot.reply_to(message, "Send some code after /run, e.g.:\n/run print(2+2)")
        return
    bot.send_chat_action(message.chat.id, "typing")
    output = run_python_code(code)
    bot.reply_to(message, f"🖥 Output:\n```\n{output}\n```", parse_mode="Markdown")


@bot.message_handler(commands=["explain"])
def explain_cmd(message):
    text = message.text.replace("/explain", "", 1).strip()
    if not text:
        bot.reply_to(message, "Send code or an error message after /explain.")
        return
    bot.send_chat_action(message.chat.id, "typing")
    answer = ask_pypal(f"Explain this simply for a Python beginner:\n\n{text}")
    bot.reply_to(message, answer, parse_mode="Markdown")


@bot.message_handler(commands=["tip"])
def tip_cmd(message):
    bot.reply_to(message, "💡 " + random.choice(TIPS))


@bot.message_handler(func=lambda m: True)
def fallback(message):
    """Anything that isn't a known command — broken code, tracebacks, questions —
    goes straight to PyPal, who follows the debugging protocol automatically."""
    bot.send_chat_action(message.chat.id, "typing")
    answer = ask_pypal(message.text)
    bot.reply_to(message, answer, parse_mode="Markdown")


if __name__ == "__main__":
    keep_alive()
    print("PyPal is running...")
    bot.infinity_polling()
