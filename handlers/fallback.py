"""
handlers/fallback.py — creator-question detection + the catch-all AI
fallback for anything that isn't a recognized command.

IMPORTANT: this module MUST be imported LAST from handlers/__init__.py.
Its handler matches every message (func=lambda m: True), so if it were
registered before the command handlers, it would intercept commands
(like /run) before they got a chance to run.
"""

from telebot import types
from core import bot, AUTHOR_NAME, CONTACT_USERNAME
from formatting import safe_reply
from ai import ask_pypal

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
