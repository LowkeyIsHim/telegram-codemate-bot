"""
Tiny web server that does nothing but say "I'm alive".
UptimeRobot (free) pings this every 5 minutes so Replit's free tier
never sees the Repl go idle, keeping PyPal running 24/7 at no cost.
"""

from flask import Flask
from threading import Thread

app = Flask(__name__)


@app.route("/")
def home():
    return "PyPal is alive!"


def run():
    app.run(host="0.0.0.0", port=8080)


def keep_alive():
    t = Thread(target=run)
    t.start()
