"""
handlers/menu.py — /start, /menu, /tip, and PyPal's navigable menu system.

The menu is structured as: main overview -> tap a category -> see just
that category's commands -> tap Back. This is defined by the CATEGORIES
dict below, so adding a new command to an existing category later is a
one-line change here (plus wherever the command itself is implemented) —
no need to touch the menu layout logic itself.
"""

import random
from telebot import types
from core import bot, AUTHOR_NAME, CONTACT_USERNAME, TIPS

DIVIDER = "▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰"

# Each category: emoji, display title, and its (command, description) pairs.
# To add a command to an existing category, just add a tuple here.
CATEGORIES = {
    "coding": {
        "emoji": "💻",
        "title": "Coding",
        "commands": [
            ("/run `<code>`", "Execute Python code, see the output"),
            ("/explain `<code or error>`", "Plain-English bug breakdown"),
            ("/lint `<code>`", "Catch bugs/style issues without running it"),
            ("/tip", "Random Python tip"),
        ],
    },
    "osint": {
        "emoji": "🕵️",
        "title": "OSINT",
        "commands": [
            ("/ipinfo `<ip/domain>`", "Geolocation, ISP, org"),
            ("/whois `<domain>`", "Domain registration info"),
            ("/headers `<url>`", "HTTP response headers"),
            ("/subdomains `<domain>`", "Passive subdomain enumeration"),
        ],
    },
    "security": {
        "emoji": "🛡",
        "title": "Security",
        "commands": [
            ("/portscan `<host>`", "Common-port TCP check"),
            ("/sslcheck `<domain>`", "SSL certificate details & expiry"),
            ("/cve `<keyword or CVE-ID>`", "Public vulnerability lookup"),
            ("/base64 `encode|decode <text>`", "Quick base64 utility"),
        ],
    },
}


def _total_command_count() -> int:
    return sum(len(cat["commands"]) for cat in CATEGORIES.values())


def _main_menu_text() -> str:
    return (
        "🐍 *PyPal* — _Command Center_\n"
        f"{DIVIDER}\n\n"
        "Your Python coding companion + security toolkit\n\n"
        f"📊 *{_total_command_count()} tools* across *{len(CATEGORIES)} categories*\n\n"
        "Select a category to explore ⤵️\n\n"
        "_Or just send broken code, a traceback, or any question directly — "
        "no command needed._"
    )


def _main_menu_markup() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup()
    cat_buttons = [
        types.InlineKeyboardButton(
            text=f"{cat['emoji']} {cat['title']} ({len(cat['commands'])})",
            callback_data=f"cat_{key}",
        )
        for key, cat in CATEGORIES.items()
    ]
    # 2-column grid for category buttons, last one alone if odd count
    for i in range(0, len(cat_buttons), 2):
        markup.row(*cat_buttons[i:i + 2])
    markup.row(types.InlineKeyboardButton(text="🎲 Random Tip", callback_data="tip"))
    markup.row(
        types.InlineKeyboardButton(
            text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
        )
    )
    return markup


def _category_text(key: str) -> str:
    cat = CATEGORIES[key]
    lines = [f"{cat['emoji']} *{cat['title']} Tools*", DIVIDER, ""]
    for cmd, desc in cat["commands"]:
        lines.append(f"▸ {cmd}")
        lines.append(f"   _{desc}_\n")
    if key in ("osint", "security"):
        lines.append(DIVIDER)
        lines.append("⚠️ _Only use on targets you own or have explicit permission to test._")
    return "\n".join(lines).strip()


def _category_markup() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup()
    markup.row(types.InlineKeyboardButton(text="🔙 Back to Menu", callback_data="menu"))
    return markup


@bot.message_handler(commands=["start", "help"])
def start(message):
    markup = types.InlineKeyboardMarkup()
    markup.row(types.InlineKeyboardButton(text="📋 Full Menu", callback_data="menu"))
    markup.row(
        types.InlineKeyboardButton(
            text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
        )
    )
    bot.reply_to(
        message,
        f"👋 Hey, I'm *PyPal* — your Python coding buddy & security toolkit, "
        f"built by {AUTHOR_NAME}.\n\n"
        "I can debug your code, explain errors, run Python snippets, and "
        "handle basic OSINT/security lookups — all from this chat.\n\n"
        "Tap *Full Menu* below to see everything, or just send me broken "
        "code or a question to get started.",
        parse_mode="Markdown",
        reply_markup=markup,
    )


@bot.message_handler(commands=["menu"])
def menu_cmd(message):
    bot.reply_to(message, _main_menu_text(), parse_mode="Markdown", reply_markup=_main_menu_markup())


@bot.message_handler(commands=["tip"])
def tip_cmd(message):
    bot.reply_to(message, "💡 " + random.choice(TIPS))


@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    if call.data == "menu":
        bot.answer_callback_query(call.id)
        bot.send_message(
            call.message.chat.id,
            _main_menu_text(),
            parse_mode="Markdown",
            reply_markup=_main_menu_markup(),
        )
    elif call.data.startswith("cat_"):
        key = call.data[len("cat_"):]
        if key in CATEGORIES:
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                _category_text(key),
                parse_mode="Markdown",
                reply_markup=_category_markup(),
            )
        else:
            bot.answer_callback_query(call.id)
    elif call.data == "tip":
        bot.answer_callback_query(call.id, text="Here's a tip!")
        bot.send_message(call.message.chat.id, "💡 " + random.choice(TIPS))
    else:
        bot.answer_callback_query(call.id)
