import http.client
import ipaddress
import os
import re
import socket
import time
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

app = FastAPI()
CRAWLERS = ("OAI-SearchBot", "Googlebot", "Google-Extended", "ClaudeBot", "Claude-SearchBot")
LIMIT = 500 * 1024
UNRESERVED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"


class Scan(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    path: str = Field(default="", max_length=2048)


def parse_url(url):
    if any(c.isspace() or ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("Enter a valid HTTP or HTTPS website.")
    parts = urlsplit(url)
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username is not None
            or parts.port not in (None, 443 if parts.scheme == "https" else 80)):
        raise ValueError("Use an HTTP or HTTPS website on its standard port.")
    parts.hostname.encode("idna")
    return parts


def fetch_robots(url):
    deadline = time.monotonic() + 8
    for _ in range(6):
        parts = parse_url(url)
        host = parts.hostname.encode("idna").decode()
        port = 443 if parts.scheme == "https" else 80
        addresses = [entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global or ip.is_multicast or (ip.version == 6 and ip.ipv4_mapped):
                raise ValueError("Only public websites can be checked.")
        timeout = deadline - time.monotonic()
        if not addresses or timeout <= 0:
            raise TimeoutError()
        connection_type = http.client.HTTPSConnection if port == 443 else http.client.HTTPConnection
        connection = connection_type(host, port, timeout=min(3, timeout))
        # Connect to the validated IP while retaining the hostname for TLS and Host.
        connection._create_connection = lambda _, timeout, source: socket.create_connection(
            (addresses[0], port), timeout, source
        )
        try:
            target = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if parts.query:
                target += "?" + quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
            connection.request("GET", target, headers={"User-Agent": "CiteLocal-AI", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308) and response.getheader("Location"):
                url = urljoin(url, response.getheader("Location"))
                continue
            if response.status != 200:
                return response.status, "", url
            body = bytearray()
            while len(body) <= LIMIT:
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                chunk = response.read1(min(16384, LIMIT + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > LIMIT:
                raise ValueError("The robots.txt file exceeds the 500 KiB scan limit.")
            if "text/html" in response.getheader("Content-Type", "").lower() or body.lstrip().startswith(b"<"):
                raise ValueError("The website returned HTML instead of robots.txt.")
            return 200, body.decode("utf-8-sig", errors="replace"), url
        finally:
            connection.close()
    raise ValueError("The robots.txt URL redirected too many times.")


def normalise(value):
    encoded = quote(value, safe="/%?:@!$&'()*+,;=~-._[]")
    return re.sub(
        r"%([0-9a-fA-F]{2})",
        lambda match: chr(int(match[1], 16)) if chr(int(match[1], 16)) in UNRESERVED else match[0].upper(),
        encoded,
    )


def rule_matches(pattern, target):
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    first, *pieces = pattern.split("*")
    if not target.startswith(first):
        return False
    offset = len(first)
    if anchored:
        if not pieces:
            return target == first
        last = pieces.pop()
        if not target.endswith(last):
            return False
        target = target[:len(target) - len(last)]
        if offset > len(target):
            return False
    for piece in pieces:
        position = target.find(piece, offset)
        if position < 0:
            return False
        offset = position + len(piece)
    return True


def parse_groups(body):
    groups = []
    agents, rules = [], []
    for line in body.splitlines():
        key, _, value = line.partition("#")[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent" and value:
            if rules:
                groups.append((agents, rules))
                agents, rules = [], []
            agents.append(value.lower())
        elif agents and key in ("allow", "disallow"):
            rules.append((key, value))
    if agents:
        groups.append((agents, rules))
    return groups


def evaluate(grouped_rules, crawler, target):
    agent = crawler.lower()
    selected = [rules for agents, rules in grouped_rules if agent in agents]
    if not selected:
        selected = [rules for agents, rules in grouped_rules if "*" in agents]
    winner = None
    for rules in selected:
        for directive, value in rules:
            if not value.startswith("/"):
                continue
            pattern = normalise(value)
            if not rule_matches(pattern, target):
                continue
            priority = (len(re.sub(r"%[0-9A-F]{2}", "x", pattern)), directive == "allow")
            if winner is None or priority > winner[0]:
                winner = (priority, directive, value)
    if winner is None:
        return "allowed", "No matching rule for this path."
    return ("allowed" if winner[1] == "allow" else "disallowed"), f"{winner[1].title()}: {winner[2]}"


@app.get("/")
def homepage():
    if os.environ.get("VERCEL"):
        return RedirectResponse("/index.html")
    return FileResponse(Path(__file__).resolve().parents[2] / "public" / "index.html")


@app.post("/api/robots-check")
def scan_robots(scan: Scan):
    website = scan.url.strip()
    if "://" not in website:
        website = "https://" + website
    try:
        parts = parse_url(website)
        target = scan.path.strip() or (parts.path or "/") + ("?" + parts.query if parts.query else "")
        if not target.startswith("/") or target.startswith("//") or "#" in target or "\\" in target:
            raise ValueError("Enter a page path beginning with / and omit any fragment.")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    source = f"{parts.scheme}://{parts.netloc}/robots.txt"
    try:
        status, body, source = fetch_robots(source)
    except ValueError as exc:
        outcome = ("unknown", str(exc))
    except (OSError, http.client.HTTPException):
        outcome = ("unknown", "The website did not return a readable robots.txt response in time.")
    else:
        if status == 200:
            outcome = None
            groups = parse_groups(body)
        elif status in (404, 410):
            outcome = ("allowed", f"No robots.txt was found (HTTP {status}).")
        else:
            outcome = ("unknown", f"The website returned HTTP {status} for robots.txt.")

    results = []
    for crawler in CRAWLERS:
        decision, reason = outcome or evaluate(groups, crawler, normalise(target))
        results.append({"crawler": crawler, "status": decision, "reason": reason})
    return {"source": source, "path": target, "results": results}
