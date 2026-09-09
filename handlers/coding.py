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


@bot.message_handler(commands=["regex"])
def regex_cmd(message):
    """Usage: /regex <pattern> | <test text>
    Also accepts pattern and text on separate lines."""
    text = message.text.replace("/regex", "", 1).strip()
    if not text:
        bot.reply_to(
            message,
            "Usage: /regex <pattern> | <test text>\n"
            "e.g. /regex ^\\d+$ | 12345\n\n"
            "Or send the pattern on one line, test text on the next.",
        )
        return

    if "\n" in text:
        pattern, test_text = text.split("\n", 1)
    elif "|" in text:
        pattern, test_text = text.split("|", 1)
    else:
        bot.reply_to(
            message,
            "Need both a pattern and test text — separate them with '|' or a newline.\n"
            "e.g. /regex ^\\d+$ | 12345",
        )
        return

    pattern, test_text = pattern.strip(), test_text.strip()
    try:
        import re as re_module
        compiled = re_module.compile(pattern)
        match = compiled.search(test_text)
        if match:
            groups = match.groups()
            reply = f"✅ *Match found!*\nMatched: `{match.group(0)}`"
            if groups:
                reply += "\nGroups: " + ", ".join(f"`{g}`" for g in groups)
        else:
            reply = "❌ *No match.*"
        safe_reply(message, reply)
    except re_module.error as e:
        bot.reply_to(message, f"⚠️ Invalid regex pattern: {e}")


@bot.message_handler(commands=["docs"])
def docs_cmd(message):
    """Quick Python stdlib doc lookup, e.g. /docs str.split or /docs os.path.join"""
    term = message.text.replace("/docs", "", 1).strip()
    if not term:
        bot.reply_to(message, "Usage: /docs <name>\ne.g. /docs str.split\ne.g. /docs os.path.join")
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        import pydoc
        doc = pydoc.render_doc(term, renderer=pydoc.plaintext)
        # Strip pydoc's noisy "Help on ..." header formatting for a cleaner reply
        if len(doc) > 1500:
            doc = doc[:1500] + "\n... (truncated)"
        safe_reply(message, f"📖 *Docs: {term}*\n```\n{doc}\n```")
    except Exception as e:
        bot.reply_to(message, f"⚠️ No docs found for '{term}': {e}")
