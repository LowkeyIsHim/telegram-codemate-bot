"""
handlers/security.py — /portscan, /cve, /base64.
"""

import base64 as b64
import socket
import ssl
from datetime import datetime, timezone
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


@bot.message_handler(commands=["sslcheck"])
def sslcheck_cmd(message):
    import ssl
    import datetime

    domain = message.text.replace("/sslcheck", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /sslcheck <domain>\ne.g. /sslcheck example.com")
        return
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    bot.send_chat_action(message.chat.id, "typing")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        try:
            expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.datetime.utcnow()).days
            expiry_note = f" ({days_left} days left)"
        except Exception:
            days_left = None
            expiry_note = ""

        sans = [s[1] for s in cert.get("subjectAltName", [])]

        reply = (
            f"🔐 *SSL Certificate: {domain}*\n"
            f"Subject: {subject.get('commonName', 'N/A')}\n"
            f"Issuer: {issuer.get('commonName', 'N/A')}\n"
            f"Valid from: {not_before}\n"
            f"Valid until: {not_after}{expiry_note}\n"
            f"Protocol: {version}\n"
            f"Cipher: {cipher[0] if cipher else 'N/A'}\n"
            f"SANs: {', '.join(sans[:10]) if sans else 'N/A'}"
        )
        if days_left is not None and days_left < 14:
            reply += "\n\n⚠️ Certificate is expiring soon!"
        safe_reply(message, reply)
    except ssl.SSLCertVerificationError as e:
        safe_reply(message, f"⚠️ Certificate verification failed: {e}\n(This itself can be a real finding on an audit.)")
    except Exception as e:
        bot.reply_to(message, f"⚠️ SSL check failed: {e}")


@bot.message_handler(commands=["sslcheck"])
def sslcheck_cmd(message):
    domain = message.text.replace("/sslcheck", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /sslcheck <domain>\ne.g. /sslcheck example.com")
        return
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    bot.send_chat_action(message.chat.id, "typing")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()

        not_before = cert.get("notBefore", "N/A")
        not_after = cert.get("notAfter", "N/A")
        try:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
        except ValueError:
            days_left = None

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        san_entries = cert.get("subjectAltName", [])
        san_list = ", ".join(v for _, v in san_entries) if san_entries else "N/A"

        reply = (
            f"🔒 *SSL Certificate: {domain}*\n"
            f"Subject: {subject.get('commonName', 'N/A')}\n"
            f"Issuer: {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}\n"
            f"Valid from: {not_before}\n"
            f"Valid until: {not_after}"
        )
        if days_left is not None:
            reply += f" ({days_left} days left)"
        reply += (
            f"\nProtocol: {proto}\n"
            f"Cipher: {cipher[0] if cipher else 'N/A'}\n"
            f"SANs: {san_list}"
        )
        if days_left is not None and days_left < 14:
            reply += "\n\n⚠️ Certificate expiring soon!"
        safe_reply(message, reply)
    except ssl.SSLCertVerificationError as e:
        safe_reply(message, f"⚠️ Certificate verification failed: {e}\n(this itself can be a useful finding)")
    except Exception as e:
        bot.reply_to(message, f"⚠️ SSL check failed: {e}")
