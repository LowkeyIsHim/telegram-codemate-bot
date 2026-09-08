"""
core.py — shared setup used by every other file: environment/secrets,
the single shared `bot` instance, and constants like your name and tips.

Every feature module imports from here instead of creating its own bot
instance — that's what lets all the @bot.message_handler decorators
across different files register on the same bot.
"""

import os
import telebot
from dotenv import load_dotenv

load_dotenv()  # reads the .env file sitting next to bot.py

BOT_TOKEN = os.environ.get("BOT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if not BOT_TOKEN:
    raise RuntimeError("Missing BOT_TOKEN. Check your .env file has BOT_TOKEN=... set.")
if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY. Check your .env file has GEMINI_API_KEY=... set.")

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
