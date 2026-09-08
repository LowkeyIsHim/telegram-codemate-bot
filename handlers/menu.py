"""
handlers/menu.py — /start, /menu, /tip, and the interactive menu buttons
(Full Menu, Random Tip, Contact Creator).
"""

import random
from telebot import types
from core import bot, AUTHOR_NAME, CONTACT_USERNAME, TIPS


def _menu_text() -> str:
    return (
        "🐍 *PyPal — Full Menu*\n"
        "_Your Python coding buddy + security toolkit_\n\n"
        "*💻 Coding*\n"
        "/run `<code>` — execute Python code, see the output\n"
        "/explain `<code or error>` — plain-English bug breakdown\n"
        "/lint `<code>` — catch bugs/style issues without running it\n"
        "/tip — random Python tip\n\n"
        "*🕵️ OSINT*\n"
        "/ipinfo `<ip/domain>` — geolocation, ISP, org\n"
        "/whois `<domain>` — domain registration info\n"
        "/headers `<url>` — HTTP response headers\n"
        "/subdomains `<domain>` — passive subdomain enumeration\n\n"
        "*🛡 Security*\n"
        "/portscan `<host>` — common-port TCP check\n"
        "/sslcheck `<domain>` — SSL certificate details & expiry\n"
        "/cve `<keyword or CVE-ID>` — public vulnerability lookup\n"
        "/base64 `encode|decode <text>` — quick base64 utility\n\n"
        "*⚠️ Use OSINT/Security tools only on targets you own or have explicit permission to test.*\n\n"
        "*No command needed:* send broken code, a traceback, or any coding "
        "question directly and PyPal debugs or explains it automatically.\n\n"
        f"Built by {AUTHOR_NAME}"
    )


def _menu_markup() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(text="🎲 Random Tip", callback_data="tip"))
    markup.add(
        types.InlineKeyboardButton(
            text="💬 Contact Creator", url=f"https://t.me/{CONTACT_USERNAME}"
        )
    )
    return markup


@bot.message_handler(commands=["start", "help"])
def start(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(text="📋 Full Menu", callback_data="menu"))
    markup.add(
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
    bot.reply_to(message, _menu_text(), parse_mode="Markdown", reply_markup=_menu_markup())


@bot.message_handler(commands=["tip"])
def tip_cmd(message):
    bot.reply_to(message, "💡 " + random.choice(TIPS))


@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    if call.data == "menu":
        bot.answer_callback_query(call.id)
        bot.send_message(
            call.message.chat.id, _menu_text(), parse_mode="Markdown", reply_markup=_menu_markup()
        )
    elif call.data == "tip":
        bot.answer_callback_query(call.id, text="Here's a tip!")
        bot.send_message(call.message.chat.id, "💡 " + random.choice(TIPS))
    else:
        bot.answer_callback_query(call.id)
