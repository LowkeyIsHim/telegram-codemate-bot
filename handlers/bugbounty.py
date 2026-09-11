"""
handlers/bugbounty.py — passive recon tools used in real bug-bounty
workflows: technology fingerprinting, historical URL discovery via the
Wayback Machine, responsible-disclosure contact lookup, and robots.txt
inspection. All passive — ordinary requests a browser would also send,
or queries to third-party public archives, never active probing.
"""

import requests
from core import bot, MAX_OUTPUT_CHARS, DIVIDER
from formatting import safe_reply
from ssrf_guard import is_blocked_target

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", 'name="generator" content="WordPress'],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "React": ["react-root", "data-reactroot"],
    "Angular": ["ng-version"],
    "Vue.js": ["data-v-app", "__vue__"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "Django": ["csrfmiddlewaretoken"],
    "Laravel": ["laravel_session"],
    "Ruby on Rails": ["csrf-param", "data-turbo"],
}


def get_techstack_text(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    blocked = is_blocked_target(url)
    if blocked:
        return blocked
    try:
        r = requests.get(url, timeout=10)
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text[:200_000]  # cap how much page text we scan

        found = []
        if headers.get("server"):
            found.append(f"Server: {headers['server']}")
        if headers.get("x-powered-by"):
            found.append(f"X-Powered-By: {headers['x-powered-by']}")

        for tech, sigs in TECH_SIGNATURES.items():
            if any(sig in body for sig in sigs):
                found.append(f"Detected: {tech}")

        set_cookie = headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            found.append("Language hint: PHP (PHPSESSID cookie)")
        if "JSESSIONID" in set_cookie:
            found.append("Language hint: Java (JSESSIONID cookie)")

        if not found:
            return f"No obvious technology fingerprints found for {url}."
        return f"🔧 *Tech Stack: {url}*\n{DIVIDER}\n\n" + "\n".join(f"• {f}" for f in found)
    except Exception as e:
        return f"⚠️ Tech detection failed: {e}"


@bot.message_handler(commands=["techstack"])
def techstack_cmd(message):
    url = message.text.replace("/techstack", "", 1).strip()
    if not url:
        bot.reply_to(message, "Usage: /techstack <url>\ne.g. /techstack example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_techstack_text(url))


def get_wayback_text(domain: str) -> str:
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 50,
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        if len(data) <= 1:  # first row is just the header ["original"]
            return f"No archived URLs found for {domain} in the Wayback Machine."
        urls = [row[0] for row in data[1:]]
        reply = f"🕰 *Wayback Machine: {domain}*\n{DIVIDER}\n\n({len(urls)} URLs, capped at 50)\n```\n"
        reply += "\n".join(urls) + "\n```"
        return reply
    except Exception as e:
        return f"⚠️ Wayback lookup failed: {e}"


@bot.message_handler(commands=["wayback"])
def wayback_cmd(message):
    domain = message.text.replace("/wayback", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /wayback <domain>\ne.g. /wayback example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_wayback_text(domain))


def get_securitytxt_text(domain: str) -> str:
    clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
    blocked = is_blocked_target(clean_domain)
    if blocked:
        return blocked
    urls = [
        f"https://{clean_domain}/.well-known/security.txt",
        f"https://{clean_domain}/security.txt",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=10, allow_redirects=True)
            # Validate it's an actual security.txt, not just any 200 page
            # (e.g. a custom 404 that still returns status 200).
            if r.status_code == 200 and ("Contact:" in r.text or "Expires:" in r.text):
                contacts, policy, expires, encryption = [], "N/A", "N/A", "N/A"
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.startswith("Contact:"):
                        contacts.append(line.split(":", 1)[1].strip())
                    elif line.startswith("Policy:"):
                        policy = line.split(":", 1)[1].strip()
                    elif line.startswith("Expires:"):
                        expires = line.split(":", 1)[1].strip()
                    elif line.startswith("Encryption:"):
                        encryption = line.split(":", 1)[1].strip()

                contact_str = "\n".join(f"• `{c}`" for c in contacts) if contacts else "• None specified"

                return (
                    f"🛡 *RFC 9116 Disclosure Info: `{clean_domain}`*\n{DIVIDER}\n\n"
                    f"*Reporting Contacts:*\n{contact_str}\n\n"
                    f"• *Policy URL:* `{policy}`\n"
                    f"• *PGP Key:* `{encryption}`\n"
                    f"• *Expires:* `{expires}`\n"
                    f"• *Source Path:* `{url}`"
                )
        except Exception:
            continue
    return f"❌ No valid RFC 9116 security.txt found for `{clean_domain}`."


@bot.message_handler(commands=["securitytxt"])
def securitytxt_cmd(message):
    domain = message.text.replace("/securitytxt", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /securitytxt <domain>\ne.g. /securitytxt example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    text = get_securitytxt_text(domain)
    try:
        bot.reply_to(message, text, parse_mode="Markdown")
    except Exception:
        # A contact/PGP value with a stray _ or * could unbalance legacy
        # Markdown — fall back to plain text rather than losing the reply.
        bot.reply_to(message, text)


def get_robots_text(domain: str) -> str:
    base = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    blocked = is_blocked_target(base)
    if blocked:
        return blocked
    try:
        r = requests.get(f"{base}/robots.txt", timeout=10)
        if r.status_code != 200:
            return f"No robots.txt found at {base}/robots.txt (status {r.status_code})."
        content = r.text.strip()
        if not content:
            return f"{base}/robots.txt exists but is empty."
        content = content[:MAX_OUTPUT_CHARS]
        return f"🤖 *robots.txt: {base}*\n{DIVIDER}\n\n```\n{content}\n```"
    except Exception as e:
        return f"⚠️ robots.txt fetch failed: {e}"


@bot.message_handler(commands=["robots"])
def robots_cmd(message):
    domain = message.text.replace("/robots", "", 1).strip()
    if not domain:
        bot.reply_to(message, "Usage: /robots <domain>\ne.g. /robots example.com")
        return
    bot.send_chat_action(message.chat.id, "typing")
    safe_reply(message, get_robots_text(domain))
