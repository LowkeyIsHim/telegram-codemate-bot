"""
handlers/coding.py — /run and /explain, PyPal's core coding-help features.
"""

from core import bot
from formatting import safe_reply
from ai import ask_pypal
from sandbox import run_python_code


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
