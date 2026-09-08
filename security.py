"""
handlers/security.py — /portscan, /cve, /base64.
"""

import base64 as b64
import socket
import requests
from core import bot
from formatting import safe_reply


@bot.message_handler(commands=["base64"])
def base64_cmd(message):
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3 or parts[1].lower() not in ("encode", "decode"):
        bot.reply_to(
            message,
            "Usage: /base64 encode|decode <text>\n"
            "e.g. /base64 encode hello world\n"
            "e.g. /base64 decode aGVsbG8gd29ybGQ=",
        )
        return
    mode, text = parts[1].lower(), parts[2]
    try:
        if mode == "encode":
            result = b64.b64encode(text.encode()).decode()
        else:
            result = b64.b64decode(text.encode()).decode()
        safe_reply(message, f"```\n{result}\n```")
    except Exception as e:
        bot.reply_to(message, f"⚠️ {mode.capitalize()} failed: {e}")


@bot.message_handler(commands=["cve"])
def cve_cmd(message):
    query = message.text.replace("/cve", "", 1).strip()
    if not query:
        bot.reply_to(
            message,
            "Usage: /cve <keyword or CVE-ID>\n"
            "e.g. /cve log4j\ne.g. /cve CVE-2021-44228",
        )
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        # NVD (National Vulnerability Database): free, public, no key needed
        # for light personal use (rate-limited without a key, which is fine here).
        if query.upper().startswith("CVE-"):
            params = {"cveId": query.upper()}
        else:
            params = {"keywordSearch": query}
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])[:3]
        if not vulns:
            safe_reply(message, f"No CVEs found for '{query}'.")
            return
        blocks = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")
            if len(desc) > 300:
                desc = desc[:300] + "..."
            metrics = cve.get("metrics", {})
            severity = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    severity = metrics[key][0]["cvssData"].get("baseScore", "N/A")
                    break
            blocks.append(f"*{cve_id}* (CVSS: {severity})\n{desc}")
        safe_reply(message, "🛡 *CVE Results*\n\n" + "\n\n".join(blocks))
    except Exception as e:
        bot.reply_to(message, f"⚠️ CVE lookup failed: {e}")


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}


@bot.message_handler(commands=["portscan"])
def portscan_cmd(message):
    host = message.text.replace("/portscan", "", 1).strip()
    if not host:
        bot.reply_to(
            message,
            "Usage: /portscan <host>\ne.g. /portscan example.com\n\n"
            f"Checks {len(COMMON_PORTS)} common ports only (not a full range scan).\n"
            "⚠️ Only scan hosts you own or have explicit permission to test.",
        )
        return
    bot.send_chat_action(message.chat.id, "typing")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        bot.reply_to(message, f"⚠️ Couldn't resolve '{host}': {e}")
        return

    open_ports = []
    for port, name in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(f"{port}/tcp  {name}")

    if not open_ports:
        safe_reply(message, f"🔒 *Port scan: {host} ({ip})*\nNo common ports found open.")
        return
    reply = f"🔓 *Port scan: {host} ({ip})*\n```\n" + "\n".join(open_ports) + "\n```"
    safe_reply(message, reply)
