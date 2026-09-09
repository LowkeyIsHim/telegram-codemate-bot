"""
handlers/osint.py — /ipinfo, /whois, /headers, /subdomains, /dns.
All of these query public data sources — no active probing of a target
beyond a plain HTTP request (/headers) or a public API lookup.

Each lookup's core logic lives in a get_*_text() function that never
raises — it catches its own errors and returns a message string either
way. That's what lets /recon (handlers/recon.py) reuse the exact same,
already-tested logic instead of duplicating it: the command handlers
below are thin wrappers that just add the Telegram-specific bits
(typing indicator, sending the reply).
"""

import requests
import dns.resolver
from core import bot, MAX_OUTPUT_CHARS
from formatting import safe_reply


def get_ipinfo_text(target: str) -> str:
    try:
        r = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = r.json()
        if data.get("status") != "success":
            return f"⚠️ IP info lookup failed: {data.get('message', 'unknown target')}"
        return (
            f"🌐 *IP Info: {data.get('query')}*\n"
            f"Country: {data.get('country')} ({data.get('countryCode')})\n"
            f"Region: {data.get('regionName')}\n"
            f"City: {data.get('city')}\n"
            f"ISP: {data.get('isp')}\n"
            f"Org: {data.get('org')}\n"
            f"AS: {data.get('as')}\n"
            f"Timezone: {data.get('timezone')}"
        )
    except Exception as e:
        return f"⚠️ IP info lookup failed: {e}"


@bot.message_handler(commands=["ipinfo"])
def ipinfo_cmd(message):
    target = message.text.replace("/ipinfo", "", 1).strip()
    if not target:
        bot.reply_to(message, "Usage: /ipinfo <ip or domain>\ne.g. /ipinfo 8.8.8.8")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_ipinfo_text(target))


def get_whois_text(domain: str) -> str:
    try:
        import whois as whois_lib
        data = whois_lib.whois(domain)
        fields = [data.registrar, data.creation_date, data.expiration_date, data.name_servers]
        if all(f is None for f in fields):
            # The parser didn't recognize this registry's format (common for
            # some ccTLDs) — fall back to raw text instead of a wall of "None".
            raw = getattr(data, "text", None) or str(data)
            raw = raw.strip()[:MAX_OUTPUT_CHARS] if raw else "No data returned."
            return (
                f"📄 *WHOIS: {domain}*\n"
                "(This registry's format isn't fully parsed — showing raw data)\n"
                f"```\n{raw}\n```"
            )
        return (
            f"📄 *WHOIS: {domain}*\n"
            f"Registrar: {data.registrar}\n"
            f"Created: {data.creation_date}\n"
            f"Expires: {data.expiration_date}\n"
            f"Name servers: {', '.join(data.name_servers) if data.name_servers else 'N/A'}"
        )
    except Exception as e:
        return (
            f"⚠️ WHOIS lookup failed ({e}). Some hosts block outbound WHOIS "
            "(port 43) — this may not work on every server."
        )


@bot.message_handler(commands=["whois"])
def whois_cmd(message):
    domain = message.text.replace("/whois", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /whois <domain>\ne.g. /whois example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_whois_text(domain))


def _fetch_headers(url):
    """Try HEAD request; on SSL hostname mismatch, retry with www.
    Returns (response, final_url, note) or raises the last exception."""
    try:
        r = requests.head(url, timeout=10, allow_redirects=True)
        return r, url, None
    except requests.exceptions.SSLError as e:
        # Common case: bare domain's cert doesn't cover it, only www. does.
        if "www." not in url:
            www_url = url.replace("://", "://www.", 1)
            try:
                r = requests.head(www_url, timeout=10, allow_redirects=True)
                note = (
                    f"⚠️ Note: {url}'s TLS certificate doesn't cover the bare "
                    f"domain (hostname mismatch) — retried with {www_url} instead. "
                    "That mismatch is itself worth flagging if this is a target you're auditing."
                )
                return r, www_url, note
            except Exception:
                pass
        raise e


def get_headers_text(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r, final_url, note = _fetch_headers(url)
        header_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        reply = f"📡 *Headers for {final_url}* (status {r.status_code})\n```\n{header_lines}\n```"
        if note:
            reply = note + "\n\n" + reply
        return reply
    except Exception as e:
        return f"⚠️ Header request failed: {e}"


@bot.message_handler(commands=["headers", "header"])
def headers_cmd(message):
    parts = message.text.split(maxsplit=1)
    url = parts[1].strip() if len(parts) > 1 else ""
    if not url:
        bot.reply_to(message, "Usage: /headers <url>\ne.g. /headers https://example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_headers_text(url))


def get_subdomains_text(domain: str) -> str:
    try:
        # crt.sh: free, no key, searches public Certificate Transparency logs —
        # fully passive, doesn't touch the target at all.
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        r.raise_for_status()
        entries = r.json()
        found = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(domain) and "*" not in name:
                    found.add(name)
        if not found:
            return f"No subdomains found for {domain} in certificate logs."
        subs = sorted(found)[:50]
        reply = f"🔎 *Subdomains for {domain}* ({len(found)} found, showing up to 50)\n```\n"
        reply += "\n".join(subs) + "\n```"
        return reply
    except Exception as e:
        return f"⚠️ Subdomain lookup failed: {e}"


@bot.message_handler(commands=["subdomains"])
def subdomains_cmd(message):
    domain = message.text.replace("/subdomains", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /subdomains <domain>\ne.g. /subdomains example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_subdomains_text(domain))


DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def get_dns_text(domain: str) -> str:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results = []
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            values = [str(r).strip('"') for r in answers]
            results.append(f"*{record_type}*\n" + "\n".join(f"  {v}" for v in values))
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return f"⚠️ Domain '{domain}' doesn't exist."
        except Exception:
            continue

    if not results:
        return f"No DNS records found for {domain}."
    return f"🌐 *DNS Records: {domain}*\n\n" + "\n\n".join(results)


@bot.message_handler(commands=["dns"])
def dns_cmd(message):
    domain = message.text.replace("/dns", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /dns <domain>\ne.g. /dns example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_dns_text(domain))
