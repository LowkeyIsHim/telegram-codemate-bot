"""
core.py — shared setup used by every other file: environment/secrets,
the single shared `bot` instance, and constants like your name and tips.

Every feature module imports from here instead of creating its own bot
instance — that's what lets all the @bot.message_handler decorators
across different files register on the same bot.
"""

import os
import time
from collections import defaultdict
import telebot
from dotenv import load_dotenv

load_dotenv()  # reads the .env file sitting next to bot.py

BOT_TOKEN = os.environ.get("BOT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
OWNER_ID = os.environ.get("OWNER_ID")

if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN. Check your .env file has BOT_TOKEN=... set.")
if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY. Check your .env file has GEMINI_API_KEY=... set.")
if not OWNER_ID:
    raise RuntimeError(
        "Missing OWNER_ID. This bot is owner-only — message @userinfobot on "
        "Telegram to get your numeric user ID, then add OWNER_ID=<your id> to .env."
    )
OWNER_ID = int(OWNER_ID)

bot = telebot.TeleBot(BOT_TOKEN)

AUTHOR_NAME = "༺𝕷𝖔𝖜𝖐𝖊𝖞 𝕳𝖊'𝖘 𝕳𝖎𝖒༻"
CONTACT_USERNAME = "Im_just_l0wkey"
MAX_OUTPUT_CHARS = 3000

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

# --- Global rate limiting -------------------------------------------------
# Applied automatically to every @bot.message_handler in every file, by
# wrapping bot.message_handler itself right here. No other file needs to
# know this exists — that's the point: one place to tune it, protection
# everywhere. Doesn't cover the /run sandbox's own CPU/memory limits
# (those are separate, in sandbox.py) — this just stops someone from
# firing commands faster than the bot (or its host) can handle.

RATE_LIMIT_MAX = 10       # max commands
RATE_LIMIT_WINDOW = 30    # seconds

_user_message_times = defaultdict(list)


def _is_rate_limited(user_id) -> bool:
    now = time.time()
    times = _user_message_times[user_id]
    while times and now - times[0] > RATE_LIMIT_WINDOW:
        times.pop(0)
    if len(times) >= RATE_LIMIT_MAX:
        return True
    times.append(now)
    return False


_original_message_handler = bot.message_handler


def _rate_limited_message_handler(*args, **kwargs):
    register = _original_message_handler(*args, **kwargs)

    def decorator(func):
        def wrapped(message, *a, **kw):
            user = getattr(message, "from_user", None)
            user_id = user.id if user else message.chat.id
            if user_id != OWNER_ID:
                bot.reply_to(message, "🔒 This bot is private and only usable by its owner.")
                return
            if _is_rate_limited(user_id):
                bot.reply_to(
                    message,
                    f"⏳ Slow down a bit — max {RATE_LIMIT_MAX} commands per "
                    f"{RATE_LIMIT_WINDOW}s. Try again shortly.",
                )
                return
            return func(message, *a, **kw)
        return register(wrapped)

    return decorator


bot.message_handler = _rate_limited_message_handler

_original_callback_query_handler = bot.callback_query_handler


def _owner_only_callback_handler(*args, **kwargs):
    register = _original_callback_query_handler(*args, **kwargs)

    def decorator(func):
        def wrapped(call, *a, **kw):
            user = getattr(call, "from_user", None)
            user_id = user.id if user else None
            if user_id != OWNER_ID:
                bot.answer_callback_query(call.id, text="This bot is private.", show_alert=True)
                return
            return func(call, *a, **kw)
        return register(wrapped)

    return decorator


bot.callback_query_handler = _owner_only_callback_handler
