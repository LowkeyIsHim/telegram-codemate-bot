"""
handlers/coding.py — /run, /explain, and /lint, PyPal's core coding-help features.
"""

import io
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


@bot.message_handler(commands=["lint"])
def lint_cmd(message):
    """Static analysis only — never executes the code. Catches undefined
    names, unused imports, syntax errors, and similar issues instantly."""
    code = message.text.replace("/lint", "", 1).strip()
    if not code:
        bot.reply_to(message, "Send code after /lint, e.g.:\n/lint import os\nprint(x)")
        return
    from pyflakes.api import check
    from pyflakes.reporter import Reporter

    out, err = io.StringIO(), io.StringIO()
    check(code, "<snippet>", Reporter(out, err))
    output = (out.getvalue() + err.getvalue()).strip()
    if not output:
        safe_reply(message, "✅ No issues found!")
    else:
        safe_reply(message, f"🔍 *Lint results:*\n```\n{output}\n```")


@bot.message_handler(commands=["lint"])
def lint_cmd(message):
    """Static analysis with pyflakes — catches undefined names, unused
    imports, syntax errors, etc. WITHOUT actually running the code."""
    code = message.text.replace("/lint", "", 1).strip()
    if not code:
        bot.reply_to(message, "Send some code after /lint, e.g.:\n/lint import os\nprint(x)")
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        import io
        from pyflakes.api import check
        from pyflakes.reporter import Reporter

        out, err = io.StringIO(), io.StringIO()
        check(code, "your_code.py", Reporter(out, err))
        output = (out.getvalue() + err.getvalue()).strip()
        if not output:
            safe_reply(message, "✅ No issues found — looks clean!")
        else:
            safe_reply(message, f"🔍 *Lint results:*\n```\n{output}\n```")
    except Exception as e:
        bot.reply_to(message, f"⚠️ Lint failed: {e}")
