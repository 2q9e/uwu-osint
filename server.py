#!/usr/bin/env python3
"""Local API for passive, public infrastructure lookups."""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "src"
MAX_BODY_BYTES = 4096
MAX_METADATA_BYTES = 10_000_000
MAX_METADATA_REQUEST_BYTES = 14_000_000
MAX_UPSTREAM_BYTES = 6_000_000
USER_AGENT = "uwu-osint/0.1 (local passive research workspace)"
BOOTSTRAP_LOCK = threading.Lock()
BOOTSTRAP_CACHE: dict[str, tuple[float, dict]] = {}
BOOTSTRAP_TTL_SECONDS = 6 * 60 * 60
PROFILE_LOCK = threading.Lock()
PROFILE_CACHE: tuple[float, dict] | None = None
PROFILE_CACHE_TTL_SECONDS = 12 * 60 * 60
PROFILE_CACHE_MAX_STALE_SECONDS = 3 * 24 * 60 * 60
PROFILE_DATA_REVISION = "062bcfe48df79fa618e96edc79dc9673f3fe5643"
PROFILE_DATA_URL = f"https://raw.githubusercontent.com/WebBreacher/WhatsMyName/{PROFILE_DATA_REVISION}/wmn-data.json"
PROFILE_DATA_LICENSE = "CC BY-SA 4.0"
SPECIAL_USE_SUFFIXES = ("alt", "example", "invalid", "localhost", "onion", "test", "local", "internal", "lan", "home", "arpa")
SPECIAL_USE_DOMAINS = ("example.com", "example.net", "example.org")


class LookupError(Exception):
    """A user-facing lookup or validation error."""


class SameHostRedirectHandler(HTTPRedirectHandler):
    """Allow HTTPS redirects only when they stay on the same host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before = urlsplit(req.full_url)
        after = urlsplit(newurl)
        if after.scheme != "https" or after.hostname != before.hostname or after.port not in (None, 443) or after.username or after.password:
            raise HTTPError(newurl, code, "Cross-host redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def fetch_json(
    url: str,
    *,
    expected_host: str,
    accept: str = "application/json",
    extra_headers: dict[str, str] | None = None,
) -> dict | list:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != expected_host or parsed.username or parsed.password:
        raise LookupError("The data source URL did not pass validation.")
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    for name, value in (extra_headers or {}).items():
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) or "\r" in value or "\n" in value:
            raise LookupError("The data source request headers did not pass validation.")
        headers[name] = value
    request = Request(url, headers=headers, method="GET")
    opener = build_opener(SameHostRedirectHandler())
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_UPSTREAM_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            raise LookupError("The source has no record for this value.") from exc
        if exc.code == 429:
            raise LookupError("The source rate-limited this request. Try again later.") from exc
        raise LookupError(f"The source returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise LookupError("Could not reach the public data source.") from exc
    if len(body) > MAX_UPSTREAM_BYTES:
        raise LookupError("The source response exceeded the local size limit.")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LookupError("The source returned invalid JSON.") from exc


def fetch_bootstrap(name: str) -> dict:
    with BOOTSTRAP_LOCK:
        cached = BOOTSTRAP_CACHE.get(name)
        if cached and time.monotonic() - cached[0] < BOOTSTRAP_TTL_SECONDS:
            return cached[1]
    data = fetch_json(
        f"https://data.iana.org/rdap/{name}.json",
        expected_host="data.iana.org",
    )
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise LookupError("IANA returned an unexpected RDAP bootstrap document.")
    with BOOTSTRAP_LOCK:
        BOOTSTRAP_CACHE[name] = (time.monotonic(), data)
    return data


def bootstrap_url(document: dict, predicate) -> str:
    for service in document.get("services", []):
        if not isinstance(service, list) or len(service) != 2:
            continue
        keys, bases = service
        if not isinstance(keys, list) or not isinstance(bases, list):
            continue
        if predicate(keys):
            for base in bases:
                if not isinstance(base, str):
                    continue
                try:
                    parsed = urlsplit(base)
                    port = parsed.port
                except ValueError:
                    continue
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or port not in (None, 443)
                    or parsed.query
                    or parsed.fragment
                ):
                    continue
                host = parsed.hostname.lower()
                try:
                    address = ipaddress.ip_address(host)
                except ValueError:
                    try:
                        _public_addresses(host)
                    except LookupError:
                        continue
                else:
                    if not address.is_global:
                        continue
                return base.rstrip("/") + "/"
    raise LookupError("IANA has no RDAP service listed for this value.")


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253 or "://" in raw or "/" in raw or "@" in raw:
        raise LookupError("Enter a public domain name, IP address, or ASN such as AS15169.")
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise LookupError("That domain name is not valid.") from exc
    if len(domain) > 253:
        raise LookupError("That domain name is too long after internationalized-name conversion.")
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(labels) < 2 or any(not label_pattern.fullmatch(label) for label in labels):
        raise LookupError("Enter a valid public domain name, IP address, or ASN such as AS15169.")
    if not labels[-1].isascii() or not any(char.isalpha() for char in labels[-1]):
        raise LookupError("Enter a valid public domain name, IP address, or ASN such as AS15169.")
    if (
        labels[-1] in SPECIAL_USE_SUFFIXES
        or any(domain == reserved or domain.endswith("." + reserved) for reserved in SPECIAL_USE_DOMAINS)
    ):
        raise LookupError("This is a special-use or internal name. No public source lookup was sent.")
    return domain


def normalize_email(value: str) -> dict:
    raw = value.strip()
    if len(raw) > 254 or raw.count("@") != 1:
        raise LookupError("Enter a valid email address.")
    local, domain_value = raw.rsplit("@", 1)
    local_pattern = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
    if (
        not local
        or len(local) > 64
        or not local_pattern.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise LookupError("Enter a valid email address with a standard dot-atom local part.")
    domain = normalize_domain(domain_value)
    if len(local) + 1 + len(domain) > 254:
        raise LookupError("That email address is too long after domain normalization.")
    return {"type": "email", "value": f"{local}@{domain}", "address": f"{local}@{domain}", "domain": domain}


def normalize_email_domain(value: str) -> dict:
    domain = normalize_domain(value)
    return {"type": "email-domain", "value": domain, "domain": domain}


def normalize_phone(value: str) -> dict:
    raw = value.strip()
    compact = re.sub(r"[\s().-]", "", raw)
    if not re.fullmatch(r"\+[1-9]\d{1,14}", compact):
        raise LookupError("Enter an international phone number in E.164 form, such as +14165550123.")
    return {"type": "phone", "value": compact, "format": "E.164", "digitCount": len(compact) - 1}


def identify(value: str) -> dict:
    raw = value.strip()
    if not raw:
        raise LookupError("Enter a domain or URL, public IP, ASN, @username, email, email-domain:example.com, or international phone number.")
    username_input = raw[1:] if raw.startswith("@") else raw[9:].strip() if raw.lower().startswith("username:") else None
    if username_input is not None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", username_input):
            raise LookupError("Enter a username with 2–40 letters, numbers, dots, underscores, or hyphens.")
        return {"type": "username", "value": username_input, "handle": username_input}
    if raw.lower().startswith("email:"):
        return normalize_email(raw[6:].strip())
    if raw.lower().startswith("email-domain:"):
        return normalize_email_domain(raw.split(":", 1)[1].strip())
    phone_input = raw[6:].strip() if raw.lower().startswith("phone:") else raw
    if raw.lower().startswith("phone:") or phone_input.startswith("+"):
        return normalize_phone(phone_input)
    asn_match = re.fullmatch(r"(?i)AS(\d{1,10})", raw)
    if asn_match:
        number = int(asn_match.group(1))
        if number > 4_294_967_295:
            raise LookupError("That ASN is out of range.")
        return {"type": "asn", "value": f"AS{number}", "number": number}
    if raw.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except ValueError as exc:
            raise LookupError("Enter a valid HTTP or HTTPS URL without credentials or a nonstandard port.") from exc
        if not parsed.hostname or parsed.username or parsed.password or port not in (None, 80, 443):
            raise LookupError("Enter a valid HTTP or HTTPS URL without credentials or a nonstandard port.")
        raw = parsed.hostname
    elif "@" in raw:
        return normalize_email(raw)
    try:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise LookupError("Enter a globally routable public IP address.")
        return {"type": "ip", "value": address.compressed, "version": address.version}
    except ValueError:
        pass
    return {"type": "domain", "value": normalize_domain(raw)}


def rdap_url_for(entity: dict) -> str:
    if entity["type"] == "domain":
        document = fetch_bootstrap("dns")
        labels = entity["value"].split(".")
        candidates = [".".join(labels[i:]) for i in range(1, len(labels))]
        candidates.sort(key=len, reverse=True)
        base = bootstrap_url(document, lambda keys: any(key.lower() in keys for key in candidates))
        return base + "domain/" + quote(entity["value"], safe="")
    if entity["type"] == "ip":
        kind = "ipv4" if entity["version"] == 4 else "ipv6"
        address = ipaddress.ip_address(entity["value"])
        document = fetch_bootstrap(kind)

        def owns_address(keys):
            for key in keys:
                try:
                    if address in ipaddress.ip_network(key, strict=False):
                        return True
                except ValueError:
                    continue
            return False

        base = bootstrap_url(document, owns_address)
        return base + "ip/" + quote(entity["value"], safe="")
    document = fetch_bootstrap("asn")
    number = entity["number"]

    def owns_asn(keys):
        for key in keys:
            try:
                start, end = key.split("-", 1)
                if int(start) <= number <= int(end):
                    return True
            except (ValueError, TypeError):
                continue
        return False

    base = bootstrap_url(document, owns_asn)
    return base + "autnum/" + str(number)


def parse_events(data: dict) -> list[dict]:
    events = []
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventDate"):
            events.append({"action": event.get("eventAction", "Event"), "date": event["eventDate"]})
    return events[:20]


def get_registration(entity: dict) -> dict:
    url = rdap_url_for(entity)
    host = urlsplit(url).hostname
    if not host:
        raise LookupError("IANA returned an invalid RDAP service URL.")
    data = fetch_json(url, expected_host=host, accept="application/rdap+json, application/json")
    if not isinstance(data, dict):
        raise LookupError("The registration source returned an unexpected record.")
    result = {
        "source": url,
        "queriedAt": now_iso(),
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "status": data.get("status", []),
        "events": parse_events(data),
        "nameservers": [],
    }
    if entity["type"] == "ip":
        result.update({
            "networkType": data.get("type"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
        })
        for cidr in data.get("cidr0_cidrs", []):
            if isinstance(cidr, dict):
                prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
                length = cidr.get("length")
                if prefix is not None and length is not None:
                    result.setdefault("cidrs", []).append(f"{prefix}/{length}")
    if entity["type"] == "asn":
        result.update({"startAutnum": data.get("startAutnum"), "endAutnum": data.get("endAutnum")})
    result["nameservers"] = sorted({
        item.get("ldhName", "").lower().rstrip(".")
        for item in data.get("nameservers", [])
        if isinstance(item, dict) and item.get("ldhName")
    })
    result["status"] = result["status"] if isinstance(result["status"], list) else []
    return result


DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "DS", "DNSKEY", "HTTPS")


def query_dns(name: str, record_type: str) -> dict:
    query_string = urlencode({"name": name, "type": record_type, "do": "true"})
    data = fetch_json(
        f"https://cloudflare-dns.com/dns-query?{query_string}",
        expected_host="cloudflare-dns.com",
        accept="application/dns-json",
    )
    if not isinstance(data, dict):
        raise LookupError("The DNS source returned an unexpected record.")
    response_code = data.get("Status")
    if type(response_code) is not int:
        raise LookupError("The DNS source returned no valid response code.")
    if response_code != 0:
        descriptions = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
        label = descriptions.get(response_code, f"DNS error {response_code}")
        if response_code == 3:
            raise LookupError("The queried DNS name does not exist (NXDOMAIN).")
        raise LookupError(f"The DNS provider returned {label}.")
    answers = data.get("Answer", [])
    return {
        "answers": [
            {"data": answer.get("data", ""), "ttl": answer.get("TTL")}
            for answer in answers
            if isinstance(answer, dict) and answer.get("data") is not None
        ],
        "authenticatedData": data.get("AD") if type(data.get("AD")) is bool else None,
    }


def get_dns(domain: str) -> dict:
    records: dict[str, list[dict]] = {}
    errors: list[str] = []
    authenticated: dict[str, bool | None] = {}

    with ThreadPoolExecutor(max_workers=len(DNS_TYPES)) as pool:
        futures = {pool.submit(query_dns, domain, record_type): record_type for record_type in DNS_TYPES}
        for future in as_completed(futures):
            record_type = futures[future]
            try:
                answer = future.result()
                records[record_type] = answer["answers"]
                authenticated[record_type] = answer["authenticatedData"]
            except LookupError as exc:
                records[record_type] = []
                authenticated[record_type] = None
                errors.append(f"{record_type}: {exc}")
    errors.sort()
    authenticated = {record_type: authenticated.get(record_type) for record_type in DNS_TYPES}
    successful_types = len(DNS_TYPES) - len(errors)
    return {
        "status": "error" if not successful_types else "partial" if errors else "ok",
        "source": "https://cloudflare-dns.com/dns-query",
        "queriedAt": now_iso(),
        "records": {record_type: records.get(record_type, []) for record_type in DNS_TYPES},
        "errors": errors,
        "dnssec": {
            "authenticatedDataByType": authenticated,
            "authenticatedQueries": sum(value is True for value in authenticated.values()),
            "checkedQueries": sum(value is not None for value in authenticated.values()),
        },
    }


def get_email_audit(domain: str, dns: dict) -> dict:
    failed_types = {str(error).partition(":")[0] for error in dns.get("errors", [])}
    txt_available = "TXT" not in failed_types
    mx_available = "MX" not in failed_types
    txt_records = dns.get("records", {}).get("TXT", [])
    spf_records = [
        item for item in txt_records
        if re.match(r"^v=spf1(?:\s|$)", str(item.get("data", "")).strip('"'), re.IGNORECASE)
    ]
    try:
        dmarc_txt_records = query_dns(f"_dmarc.{domain}", "TXT")["answers"]
        dmarc_error = None
    except LookupError as exc:
        dmarc_txt_records = []
        dmarc_error = None if "NXDOMAIN" in str(exc) else str(exc)
    dmarc_records = [
        item for item in dmarc_txt_records
        if re.match(r"^v=dmarc1(?:;|$)", str(item.get("data", "")).strip('"'), re.IGNORECASE)
    ]
    mx_records = dns.get("records", {}).get("MX", [])
    spf_status = "ambiguous" if len(spf_records) > 1 else "published" if spf_records else "missing" if txt_available else "unknown"
    dmarc_status = "ambiguous" if len(dmarc_records) > 1 else "published" if dmarc_records else "missing" if not dmarc_error else "unknown"
    return {
        "source": "https://cloudflare-dns.com/dns-query",
        "queriedAt": now_iso(),
        "domain": domain,
        "mxRecords": mx_records,
        "mxStatus": "published" if mx_records else "missing" if mx_available else "unknown",
        "spfRecords": spf_records,
        "spfStatus": spf_status,
        "dmarcRecords": dmarc_records,
        "dmarcStatus": dmarc_status,
        "dmarcError": dmarc_error,
        "notice": "Checks public mail-domain DNS only. SPF and DMARC statuses indicate matching record presence and duplicate ambiguity, not full policy validity. It does not verify a mailbox, identify a person, or test message delivery.",
    }


def get_phone_validation(entity: dict) -> dict:
    return {
        "source": "Local E.164 format check",
        "queriedAt": now_iso(),
        "normalized": entity["value"],
        "format": "E.164",
        "digitCount": entity["digitCount"],
        "validShape": True,
        "networkRequested": False,
        "notice": "This is a syntax check only. No subscriber, carrier, location, or account information was queried.",
    }


def get_reverse_dns(address: str) -> dict:
    parsed = ipaddress.ip_address(address)
    reverse_name = parsed.reverse_pointer
    answers = query_dns(reverse_name, "PTR")["answers"]
    return {
        "source": "https://cloudflare-dns.com/dns-query",
        "queriedAt": now_iso(),
        "address": parsed.compressed,
        "reverseName": reverse_name,
        "names": sorted({str(item.get("data", "")).rstrip(".").lower() for item in answers if item.get("data")}),
        "notice": "Reverse DNS is controlled by the address-range operator. Names may be missing or stale and do not verify who uses an address.",
    }


def get_certificates(domain: str) -> dict:
    query_string = urlencode({"q": f"%.{domain}", "output": "json"})
    data = fetch_json(f"https://crt.sh/?{query_string}", expected_host="crt.sh")
    if not isinstance(data, list):
        raise LookupError("Certificate Search returned an unexpected response.")
    names = {}
    suffix = "." + domain
    for cert in data:
        if not isinstance(cert, dict):
            continue
        for line in str(cert.get("name_value", "")).splitlines():
            name = line.strip().lower().rstrip(".")
            wildcard = name.startswith("*.")
            normalized = name[2:] if wildcard else name
            if normalized == domain or normalized.endswith(suffix):
                first_seen = cert.get("entry_timestamp")
                try:
                    parsed_first_seen = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
                    if parsed_first_seen.tzinfo is None:
                        parsed_first_seen = parsed_first_seen.replace(tzinfo=timezone.utc)
                    first_seen = parsed_first_seen.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                except (TypeError, ValueError):
                    first_seen = None
                existing = names.get(normalized)
                if existing is None:
                    names[normalized] = {
                        "name": normalized,
                        "wildcard": wildcard,
                        "firstSeen": first_seen,
                        "issuers": [cert["issuer_name"]] if cert.get("issuer_name") else [],
                    }
                else:
                    existing["wildcard"] = existing["wildcard"] or wildcard
                    if first_seen and (not existing["firstSeen"] or first_seen < existing["firstSeen"]):
                        existing["firstSeen"] = first_seen
                    issuer = cert.get("issuer_name")
                    if issuer and issuer not in existing["issuers"]:
                        existing["issuers"].append(issuer)
                        existing["issuers"].sort(key=str.casefold)
    sorted_names = sorted(names.values(), key=lambda item: item["name"])
    return {
        "source": "https://crt.sh/?" + query_string,
        "queriedAt": now_iso(),
        "names": sorted_names[:2000],
        "truncated": len(sorted_names) > 2000,
    }


def run_module(function, *args):
    try:
        return {"status": "ok", **function(*args)}
    except LookupError as exc:
        return {"status": "error", "error": str(exc), "queriedAt": now_iso()}
    except Exception:
        # Keep details from local/runtime internals out of the browser response.
        return {"status": "error", "error": "The lookup could not be completed.", "queriedAt": now_iso()}


def list_open_source_tools() -> dict:
    tools = [
        {
            "id": "domain-footprint",
            "name": "Domain footprint",
            "purpose": "Combine registry, DNS, certificate, passive hostname, historical crawl, and optional URLScan public scan observations.",
            "available": True,
            "mode": "Built-in collectors",
            "url": "https://index.commoncrawl.org/",
            "integration": "native",
        },
        {
            "id": "urlscan-historical-search",
            "name": "urlscan.io historical scan search",
            "purpose": "Search public historical scan records for scoped domain hostnames and observation times.",
            "available": bool(os.environ.get("URLSCAN_API_KEY", "").strip()),
            "mode": "Optional API key · read-only search · user selected",
            "url": "https://docs.urlscan.io/apis/urlscan-openapi/search",
            "integration": "native",
        },
        {
            "id": "account-footprint",
            "name": "Account footprint",
            "purpose": "Check public profile URLs for a username you own or are authorized to audit.",
            "available": True,
            "mode": "Live checks · user initiated",
            "url": PROFILE_DATA_URL,
            "integration": "native",
        },
        {
            "id": "email-domain-audit",
            "name": "Email domain audit",
            "purpose": "Inspect MX, SPF, and DMARC DNS for the domain part of an authorized email address.",
            "available": True,
            "mode": "Domain-only DNS and RDAP · no mailbox lookup",
            "url": "https://cloudflare-dns.com/dns-query",
            "integration": "native",
        },
        {
            "id": "phone-format",
            "name": "Phone format check",
            "purpose": "Normalize an international number locally to E.164 syntax without subscriber lookups.",
            "available": True,
            "mode": "Local format check · no network request",
            "url": "",
            "integration": "native",
        },
        {
            "id": "metadata",
            "name": "File metadata",
            "purpose": "Inspect common image and document metadata locally, including location and author tags.",
            "available": True,
            "mode": "Built-in parser · file stays local",
            "url": "",
            "integration": "native",
        },
        {
            "id": "report-import",
            "name": "Report workspace",
            "purpose": "Import scoped infrastructure evidence from common JSON, JSONL, and CSV reports.",
            "available": True,
            "mode": "Local JSON/JSONL/CSV import",
            "url": "",
            "integration": "native",
        },
    ]
    return {"tools": tools}


def fetch_text(url: str, *, expected_host: str, maximum: int = 2_000_000, timeout: int = 12) -> tuple[int, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != expected_host or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise LookupError("The data source URL did not pass validation.")
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain, text/html, application/json"}, method="GET")
    opener = build_opener(SameHostRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise LookupError("The source response exceeded the local size limit; partial data was discarded.")
            return response.status, body.decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read(maximum + 1)
        if len(body) > maximum:
            raise LookupError("The source response exceeded the local size limit; partial data was discarded.") from exc
        body = body.decode("utf-8", errors="replace")
        return exc.code, body
    except (URLError, TimeoutError, OSError) as exc:
        raise LookupError("Could not reach the public data source.") from exc


def _public_addresses(host: str, port: int = 443) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        addresses = {
            ipaddress.ip_address(result[4][0].split("%", 1)[0])
            for result in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        raise LookupError("The profile host did not resolve to public addresses.") from None
    if not addresses or any(not address.is_global for address in addresses):
        raise LookupError("The profile host did not resolve exclusively to public addresses.")
    return sorted(addresses, key=lambda address: (address.version, int(address)))


def fetch_profile_url(url: str) -> tuple[int, str]:
    original_host = None
    current_url = url
    for redirect_count in range(5):
        try:
            parsed = urlsplit(current_url)
            port = parsed.port
        except ValueError as exc:
            raise LookupError("The profile definition has an invalid URL.") from exc
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or port not in (None, 443):
            raise LookupError("The profile definition has an invalid URL.")
        host = parsed.hostname.lower()
        try:
            host = normalize_domain(host)
        except LookupError as exc:
            raise LookupError("The profile definition has an invalid host.") from exc
        if original_host is None:
            original_host = host
        elif host != original_host:
            raise LookupError("Cross-host profile redirects are blocked.")

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        redirect_url = None
        failures = []
        for address in _public_addresses(host):
            connection = http.client.HTTPSConnection(host, 443, timeout=8, context=ssl.create_default_context())
            try:
                raw_socket = socket.create_connection((address.compressed, 443), timeout=8)
                connection.sock = connection._context.wrap_socket(raw_socket, server_hostname=host)
                connection.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                    "Connection": "close",
                })
                response = connection.getresponse()
                body = response.read(250_001)
                if len(body) > 250_000:
                    raise LookupError("The profile response exceeded the local size limit; partial data was discarded.")
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location:
                        return response.status, body.decode("utf-8", errors="replace")
                    redirect_url = urljoin(current_url, location)
                    break
                return response.status, body.decode("utf-8", errors="replace")
            except LookupError:
                raise
            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
                failures.append(exc)
            finally:
                connection.close()
        if redirect_url:
            if redirect_count == 4:
                raise LookupError("The profile site redirected too many times.")
            current_url = redirect_url
            continue
        if failures:
            raise LookupError("The site did not respond.") from failures[-1]
        raise LookupError("The profile host did not resolve to a public address.")
    raise LookupError("The profile site redirected too many times.")


def profile_definitions() -> dict:
    global PROFILE_CACHE
    with PROFILE_LOCK:
        cached = PROFILE_CACHE
        if cached and time.monotonic() - cached[0] < PROFILE_CACHE_TTL_SECONDS:
            return cached[1]
    try:
        data = fetch_json(PROFILE_DATA_URL, expected_host="raw.githubusercontent.com")
        if not isinstance(data, dict) or not isinstance(data.get("sites"), list) or len(data["sites"]) > 20_000:
            raise LookupError("The public profile catalog returned an unexpected document.")
    except LookupError:
        if cached and time.monotonic() - cached[0] <= PROFILE_CACHE_MAX_STALE_SECONDS:
            return {**cached[1], "_catalogStale": True}
        raise
    with PROFILE_LOCK:
        PROFILE_CACHE = (time.monotonic(), data)
    return data


def profile_site_selection(category: str = "all", limit: int = 25) -> tuple[dict, list[str], list[dict]]:
    data = profile_definitions()
    safe_sites = [
        site for site in data["sites"]
        if isinstance(site, dict)
        and isinstance(site.get("uri_check"), str)
        and len(site["uri_check"]) <= 2_048
        and "{account}" in site["uri_check"]
        and not site.get("protection")
    ]
    categories = sorted(
        {str(site.get("cat", "other")).strip()[:60] or "other" for site in safe_sites},
        key=str.casefold,
    )
    if category != "all" and category not in categories:
        raise LookupError("Choose a category listed in the account footprint view.")
    grouped: dict[str, list[dict]] = {}
    for site in sorted(safe_sites, key=lambda item: (str(item.get("cat", "")), str(item.get("name", "")))):
        site_category = str(site.get("cat", "other")).strip()[:60] or "other"
        if category == "all" or site_category == category:
            grouped.setdefault(site_category, []).append(site)
    maximum = max(1, min(int(limit), 40))
    selected = []
    while len(selected) < maximum and any(grouped.values()):
        for category_name in sorted(grouped, key=str.casefold):
            if grouped[category_name] and len(selected) < maximum:
                selected.append(grouped[category_name].pop(0))
    return data, categories, selected


def get_account_categories() -> list[str]:
    _, categories, _ = profile_site_selection()
    return categories


def get_account_preview(category: str = "all", limit: int = 25) -> dict:
    data, categories, selected = profile_site_selection(category, limit)
    preview = []
    for site in selected:
        try:
            check_url = str(site["uri_check"]).format(account="uwu-osint-preview")
            parsed = urlsplit(check_url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
                continue
            host = normalize_domain(parsed.hostname.lower())
        except (KeyError, LookupError, ValueError):
            continue
        preview.append({
            "name": str(site.get("name", "Unknown site"))[:80],
            "category": str(site.get("cat", "other"))[:60],
            "host": host,
        })
    return {
        "categories": categories,
        "preview": preview,
        "catalogRevision": PROFILE_DATA_REVISION,
        "catalogStale": data.get("_catalogStale") is True,
    }


def _check_profile(site: dict, handle: str) -> dict:
    name = str(site.get("name", "Unknown site"))[:80]
    try:
        profile_url = str(site["uri_check"]).format(account=quote(handle, safe=""))
        status_code, body = fetch_profile_url(profile_url)
        expected_code = int(site.get("e_code", 200))
        missing_code = int(site.get("m_code", 404))
        expected_text = str(site.get("e_string", ""))
        missing_text = str(site.get("m_string", ""))
        if status_code == expected_code and expected_text and expected_text in body and (not missing_text or missing_text not in body):
            result = "found"
            evidence = "Expected profile marker matched the response."
        elif status_code == missing_code and (not missing_text or missing_text in body):
            result = "not_found"
            evidence = "The catalog's not-found status rule matched."
        elif missing_text and missing_text in body:
            result = "not_found"
            evidence = "The catalog's not-found text rule matched."
        else:
            result = "unknown"
            evidence = "The response did not match either catalog rule."
        return {"site": name, "category": site.get("cat", "other"), "status": result, "evidence": evidence, "url": profile_url}
    except (LookupError, KeyError, ValueError, OSError):
        return {"site": name, "category": site.get("cat", "other"), "status": "unknown", "evidence": "The request was blocked, unavailable, or could not be checked against the rule.", "url": None}


def get_account_footprint(entity: dict, authorized: bool, category: str = "all", limit: int = 25) -> dict:
    if not authorized:
        raise LookupError("Confirm this is an account you own or are authorized to audit.")
    data, _, selected = profile_site_selection(category, limit)
    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_check_profile, site, entity["handle"]) for site in selected]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: (item["category"], item["site"].lower()))
    return {
        "status": "ok",
        "handle": entity["handle"],
        "queriedAt": now_iso(),
        "source": PROFILE_DATA_URL,
        "license": PROFILE_DATA_LICENSE,
        "category": category,
        "checked": len(results),
        "found": sum(item["status"] == "found" for item in results),
        "notFound": sum(item["status"] == "not_found" for item in results),
        "unknown": sum(item["status"] == "unknown" for item in results),
        "sites": results,
        "catalogRevision": PROFILE_DATA_REVISION,
        "catalogStale": data.get("_catalogStale") is True,
        "notice": ("The profile catalog could not refresh; cached rules were used. " if data.get("_catalogStale") else "") + "A match only means the public profile URL responded as expected. It does not prove who controls the account.",
    }


def get_hackertarget_hosts(domain: str) -> dict:
    query = urlencode({"q": domain})
    url = f"https://api.hackertarget.com/hostsearch/?{query}"
    status_code, body = fetch_text(url, expected_host="api.hackertarget.com")
    if status_code != 200:
        raise LookupError(f"Host Search returned HTTP {status_code}.")
    if "error" in body[:120].lower() and "," not in body[:120]:
        raise LookupError("Host Search could not complete this query. Try again later.")
    suffix = "." + domain
    records = {}
    for line in body.splitlines()[:2000]:
        parts = [part.strip() for part in line.split(",", 1)]
        if len(parts) != 2:
            continue
        try:
            host = normalize_domain(parts[0])
            address = ipaddress.ip_address(parts[1])
        except (LookupError, ValueError):
            continue
        if host != domain and not host.endswith(suffix):
            continue
        if not address.is_global:
            continue
        records.setdefault(host, set()).add(address.compressed)
    return {
        "source": "https://api.hackertarget.com/hostsearch/",
        "queriedAt": now_iso(),
        "hosts": [{"name": host, "addresses": sorted(addresses)} for host, addresses in sorted(records.items())],
        "truncated": len(body.splitlines()) > 2000,
    }


def lookup_host_addresses(host: str) -> dict:
    answers = []
    errors = []
    successful_types = 0
    for record_type in ("A", "AAAA"):
        try:
            response = query_dns(host, record_type)
            successful_types += 1
            for answer in response["answers"]:
                if answer.get("data"):
                    try:
                        address = ipaddress.ip_address(answer["data"])
                        if address.is_global:
                            answers.append(address.compressed)
                    except ValueError:
                        continue
        except LookupError as exc:
            errors.append(f"{record_type}: {exc}")
    return {
        "addresses": sorted(set(answers)),
        "resolutionStatus": "error" if not successful_types else "partial" if errors else "ok",
        "resolutionErrors": errors,
    }


DOMAIN_SOURCE_IDS = ("crtsh", "hackertarget", "commoncrawl", "urlscan")
DOMAIN_SOURCE_DEFAULTS = ("crtsh", "hackertarget")


def normalize_domain_sources(value) -> tuple[str, ...]:
    if value is None:
        return DOMAIN_SOURCE_DEFAULTS
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise LookupError("Choose one or more supported passive hostname sources.")
    selected = tuple(dict.fromkeys(value))
    unknown = set(selected) - set(DOMAIN_SOURCE_IDS)
    if unknown:
        raise LookupError("One or more passive hostname sources are not supported.")
    if not selected:
        raise LookupError("Select at least one passive hostname source.")
    return selected


def get_urlscan_hosts(domain: str) -> dict:
    """Read a bounded page of historical public urlscan results for one domain."""
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        raise LookupError("URLScan was selected, but URLSCAN_API_KEY is not configured on the local server.")
    if len(api_key) > 256 or not re.fullmatch(r"[A-Za-z0-9._-]{8,256}", api_key):
        raise LookupError("The local URLScan API key has an invalid format.")
    query = urlencode({"q": f"page.domain:{domain}", "size": 100})
    data = fetch_json(
        f"https://urlscan.io/api/v1/search?{query}",
        expected_host="urlscan.io",
        extra_headers={"api-key": api_key},
    )
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise LookupError("URLScan returned an unexpected search response.")

    suffix = "." + domain
    observed: dict[str, str] = {}
    invalid_records = 0
    for result in data["results"][:100]:
        if not isinstance(result, dict):
            invalid_records += 1
            continue
        page = result.get("page") if isinstance(result.get("page"), dict) else {}
        task = result.get("task") if isinstance(result.get("task"), dict) else {}
        candidate = str(page.get("domain") or task.get("domain") or "").lower().rstrip(".")
        if not candidate and page.get("url"):
            try:
                candidate = urlsplit(str(page["url"])).hostname or ""
            except ValueError:
                candidate = ""
        try:
            host = normalize_domain(candidate)
        except LookupError:
            invalid_records += 1
            continue
        if host == domain or not host.endswith(suffix):
            continue
        sort_value = result.get("sort")
        observed_at = str(task.get("time") or (sort_value[0] if isinstance(sort_value, list) and sort_value else ""))
        if observed_at:
            try:
                parsed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                if parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(tzinfo=timezone.utc)
                observed_at = parsed_time.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except ValueError:
                observed_at = ""
        if host not in observed or observed_at > observed[host]:
            observed[host] = observed_at

    return {
        "source": "https://urlscan.io/search/",
        "queriedAt": now_iso(),
        "hosts": [{"name": host, "lastSeen": timestamp} for host, timestamp in sorted(observed.items())],
        "truncated": len(data["results"]) >= 100 or bool(data.get("has_more")),
        "invalidRecords": invalid_records,
        "resultCount": int(data.get("total", len(data["results"]))) if str(data.get("total", len(data["results"]))).isdigit() else len(data["results"]),
    }


def get_commoncrawl_hosts(domain: str) -> dict:
    collections = fetch_json("https://index.commoncrawl.org/collinfo.json", expected_host="index.commoncrawl.org")
    if not isinstance(collections, list):
        raise LookupError("Common Crawl returned an unexpected collection list.")
    available = []
    for item in collections:
        if not isinstance(item, dict):
            continue
        collection_id = item.get("id")
        match = re.fullmatch(r"CC-MAIN-(\d{4})-(\d{2})", str(collection_id or ""))
        if match:
            available.append(((int(match.group(1)), int(match.group(2))), collection_id))
    if not available:
        raise LookupError("Common Crawl did not list a current URL index.")
    collection_id = max(available)[1]
    params = urlencode({
        "url": domain,
        "matchType": "domain",
        "filter": ["status:200", "mime:text/html"],
        "fields": "url,timestamp",
        "output": "json",
        "collapse": "urlkey",
        "limit": 1000,
    }, doseq=True)
    source_url = f"https://index.commoncrawl.org/{collection_id}-index?{params}"
    status_code, body = fetch_text(source_url, expected_host="index.commoncrawl.org", maximum=1_000_000, timeout=20)
    if status_code != 200:
        if status_code == 429:
            raise LookupError("Common Crawl rate-limited this request. Try again later.")
        raise LookupError(f"Common Crawl returned HTTP {status_code}.")
    suffix = "." + domain
    hosts = {}
    invalid_records = 0
    lines = [line for line in body.splitlines() if line.strip()]
    for line in lines[:1000]:
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                invalid_records += 1
                continue
            parsed = urlsplit(str(record.get("url", "")))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                invalid_records += 1
                continue
            host = normalize_domain(parsed.hostname)
        except (json.JSONDecodeError, LookupError, ValueError):
            invalid_records += 1
            continue
        if host == domain or not host.endswith(suffix):
            continue
        timestamp = str(record.get("timestamp", ""))
        if not re.fullmatch(r"\d{14}", timestamp):
            timestamp = ""
        elif timestamp:
            try:
                datetime.strptime(timestamp, "%Y%m%d%H%M%S")
            except ValueError:
                timestamp = ""
        current = hosts.get(host)
        if current is None or timestamp > current:
            hosts[host] = timestamp
    rows = [
        {"name": host, "lastArchived": datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") if timestamp else None}
        for host, timestamp in sorted(hosts.items())
    ]
    return {
        "source": source_url,
        "archive": collection_id,
        "queriedAt": now_iso(),
        "hosts": rows[:1000],
        "truncated": len(lines) >= 1000 or len(rows) > 1000,
        "invalidRecords": invalid_records,
    }


def get_subdomain_map(domain: str, certificates: dict, domain_sources: tuple[str, ...] = DOMAIN_SOURCE_DEFAULTS) -> dict:
    selected = set(domain_sources)
    provider_results = {
        "hackertarget": {"status": "skipped", "source": "https://api.hackertarget.com/hostsearch/", "hosts": []},
        "commoncrawl": {"status": "skipped", "source": "https://index.commoncrawl.org/", "hosts": []},
        "urlscan": {"status": "skipped", "source": "https://urlscan.io/search/", "hosts": []},
    }
    with ThreadPoolExecutor(max_workers=3) as pool:
        provider_jobs = {}
        if "hackertarget" in selected:
            provider_jobs["hackertarget"] = pool.submit(run_module, get_hackertarget_hosts, domain)
        if "commoncrawl" in selected:
            provider_jobs["commoncrawl"] = pool.submit(run_module, get_commoncrawl_hosts, domain)
        if "urlscan" in selected:
            provider_jobs["urlscan"] = pool.submit(run_module, get_urlscan_hosts, domain)
        for source_id, future in provider_jobs.items():
            provider_results[source_id] = future.result()
    hostsearch = provider_results["hackertarget"]
    commoncrawl = provider_results["commoncrawl"]
    urlscan = provider_results["urlscan"]
    findings: dict[str, set[str]] = {}
    archive_dates: dict[str, dict[str, str]] = {}
    observed_dates: dict[str, dict[str, str]] = {}
    if "crtsh" in selected and certificates.get("status") == "ok":
        for item in certificates.get("names", []):
            if not item.get("wildcard"):
                findings.setdefault(item["name"], set()).add("crt.sh")
    if "hackertarget" in selected and hostsearch.get("status") == "ok":
        for item in hostsearch.get("hosts", []):
            findings.setdefault(item["name"], set()).add("HackerTarget")
    if "commoncrawl" in selected and commoncrawl.get("status") == "ok":
        for item in commoncrawl.get("hosts", []):
            findings.setdefault(item["name"], set()).add("Common Crawl")
            if item.get("lastArchived"):
                archive_dates.setdefault(item["name"], {})["Common Crawl"] = item["lastArchived"]
    if "urlscan" in selected and urlscan.get("status") == "ok":
        for item in urlscan.get("hosts", []):
            findings.setdefault(item["name"], set()).add("urlscan.io")
            if item.get("lastSeen"):
                observed_dates.setdefault(item["name"], {})["urlscan.io"] = item["lastSeen"]
    findings.pop(domain, None)
    hostnames = sorted(findings)
    unresolved = hostnames[:25]
    resolved = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(lookup_host_addresses, host): host for host in unresolved}
        for future in as_completed(futures):
            host = futures[future]
            try:
                resolved[host] = future.result()
            except Exception:
                resolved[host] = {"addresses": [], "resolutionStatus": "error", "resolutionErrors": []}
    hosts = [
        {
            "name": host,
            "sources": sorted(findings[host]),
            "archiveDates": archive_dates.get(host, {}),
            "observedDates": observed_dates.get(host, {}),
            "addresses": resolved.get(host, {}).get("addresses", []),
            "resolutionAttempted": host in resolved,
            "resolutionStatus": resolved.get(host, {}).get("resolutionStatus"),
            "resolutionErrors": resolved.get(host, {}).get("resolutionErrors", []),
        }
        for host in hostnames
    ]
    providers = [
        {
            "id": "crtsh", "name": "Certificate transparency", "status": certificates.get("status"),
            "count": len(certificates.get("names", [])), "source": certificates.get("source"),
            "error": certificates.get("error"), "truncated": bool(certificates.get("truncated")),
        },
        {
            "id": "hackertarget", "name": "HackerTarget Host Search", "status": hostsearch.get("status"),
            "count": len(hostsearch.get("hosts", [])), "source": hostsearch.get("source"),
            "error": hostsearch.get("error"), "truncated": bool(hostsearch.get("truncated")),
        },
        {
            "id": "commoncrawl", "name": "Common Crawl URL Index", "status": commoncrawl.get("status"),
            "count": len(commoncrawl.get("hosts", [])), "source": commoncrawl.get("source"),
            "error": commoncrawl.get("error"), "truncated": bool(commoncrawl.get("truncated")),
            "archive": commoncrawl.get("archive"), "invalidRecords": commoncrawl.get("invalidRecords", 0),
        },
        {
            "id": "urlscan", "name": "urlscan.io public scan search", "status": urlscan.get("status"),
            "count": len(urlscan.get("hosts", [])), "source": urlscan.get("source"),
            "error": urlscan.get("error"), "truncated": bool(urlscan.get("truncated")),
            "invalidRecords": urlscan.get("invalidRecords", 0), "resultCount": urlscan.get("resultCount", 0),
        },
    ]
    selected_providers = [provider for provider in providers if provider["id"] in selected]
    successful_providers = [provider for provider in selected_providers if provider["status"] == "ok"]
    failed_providers = [provider for provider in selected_providers if provider["status"] == "error"]
    any_source_ok = bool(successful_providers)
    overall_status = "error" if not any_source_ok else "partial" if failed_providers else "ok"
    return {
        "status": overall_status,
        "source": "https://api.hackertarget.com/hostsearch/",
        "queriedAt": now_iso(),
        "hosts": hosts[:500],
        "totalFound": len(hostnames),
        "resolvedCount": sum(bool(item["addresses"]) for item in hosts),
        "truncated": len(hostnames) > 500 or bool(hostsearch.get("truncated")) or bool(certificates.get("truncated")) or bool(commoncrawl.get("truncated")) or bool(urlscan.get("truncated")),
        "resolutionLimit": 25,
        "providers": providers,
        "selectedSources": sorted(selected),
        "error": None if any_source_ok else "No selected passive hostname source returned data.",
    }


METADATA_SUFFIXES = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".pdf", ".docx"}
TIFF_TAGS = {
    0x010F: "Camera make", 0x0110: "Camera model", 0x0131: "Editing software",
    0x0132: "File date/time", 0x013B: "Author", 0x8298: "Copyright",
    0x9003: "Photo taken", 0x9004: "Digitized", 0xA431: "Camera serial number",
    0xA434: "Lens model", 0xA420: "Image ID",
}


def parse_tiff_metadata(data: bytes) -> list[dict]:
    if data.startswith(b"Exif\x00\x00"):
        data = data[6:]
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return []
    endian = "<" if data[:2] == b"II" else ">"
    if struct.unpack_from(endian + "H", data, 2)[0] != 42:
        return []
    fields = []
    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 8: 2, 9: 4, 10: 8}

    def value_at(entry: bytes):
        tag, value_type, count = struct.unpack(endian + "HHI", entry[:8])
        if value_type not in type_sizes or count > 1000:
            return tag, None
        size = type_sizes[value_type] * count
        if size <= 4:
            raw = entry[8:8 + size]
        else:
            offset = struct.unpack(endian + "I", entry[8:12])[0]
            if offset < 0 or offset + size > len(data):
                return tag, None
            raw = data[offset:offset + size]
        if value_type in (2, 7):
            return tag, raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip() if value_type == 2 else raw
        if value_type in (1,):
            return tag, list(raw)
        if value_type in (3, 4, 8, 9):
            fmt = {3: "H", 4: "I", 8: "h", 9: "i"}[value_type]
            return tag, list(struct.unpack(endian + fmt * count, raw)) if count else []
        if value_type in (5, 10):
            fmt = "II" if value_type == 5 else "ii"
            values = []
            for index in range(count):
                numerator, denominator = struct.unpack_from(endian + fmt, raw, index * 8)
                values.append(numerator / denominator if denominator else 0)
            return tag, values
        return tag, None

    def parse_ifd(offset: int, wanted: set[int]) -> dict:
        if offset <= 0 or offset + 2 > len(data):
            return {}
        count = struct.unpack_from(endian + "H", data, offset)[0]
        if count > 2000 or offset + 2 + count * 12 + 4 > len(data):
            return {}
        values = {}
        for index in range(count):
            entry = data[offset + 2 + index * 12:offset + 14 + index * 12]
            tag, value = value_at(entry)
            if tag in wanted and value is not None:
                values[tag] = value
        return values

    try:
        first_ifd = struct.unpack_from(endian + "I", data, 4)[0]
        root = parse_ifd(first_ifd, set(TIFF_TAGS) | {0x8769, 0x8825})
        exif = parse_ifd(root.get(0x8769, [0])[0] if isinstance(root.get(0x8769), list) else root.get(0x8769, 0), set(TIFF_TAGS))
        for tag, label in TIFF_TAGS.items():
            value = exif.get(tag, root.get(tag))
            if isinstance(value, str) and value:
                fields.append({"tag": label, "value": value})
            elif isinstance(value, list) and value:
                fields.append({"tag": label, "value": ", ".join(str(item) for item in value)})
        gps_offset = root.get(0x8825, [0])
        if isinstance(gps_offset, list):
            gps_offset = gps_offset[0] if gps_offset else 0
        gps = parse_ifd(int(gps_offset), set(range(0, 32)))
        lat = gps.get(2)
        lon = gps.get(4)
        if isinstance(lat, list) and len(lat) == 3 and isinstance(lon, list) and len(lon) == 3:
            latitude = lat[0] + lat[1] / 60 + lat[2] / 3600
            longitude = lon[0] + lon[1] / 60 + lon[2] / 3600
            if gps.get(1) == "S": latitude *= -1
            if gps.get(3) == "W": longitude *= -1
            fields.extend([
                {"tag": "GPS latitude", "value": round(latitude, 7)},
                {"tag": "GPS longitude", "value": round(longitude, 7)},
            ])
        altitude = gps.get(6)
        if isinstance(altitude, list) and altitude:
            fields.append({"tag": "GPS altitude", "value": altitude[0]})
    except (struct.error, OverflowError, ValueError):
        return fields
    return fields


def parse_file_metadata(content: bytes, suffix: str) -> list[dict]:
    fields = []
    if suffix in {".jpg", ".jpeg"} or content.startswith(b"II*\x00") or content.startswith(b"MM\x00*"):
        if suffix not in {".tif", ".tiff"}:
            offset = 2 if content.startswith(b"\xff\xd8") else 0
            while offset + 4 <= len(content) and content.startswith(b"\xff", offset):
                marker = content[offset + 1]
                if marker in (0xD9, 0xDA): break
                segment_length = int.from_bytes(content[offset + 2:offset + 4], "big")
                if segment_length < 2 or offset + 2 + segment_length > len(content): break
                segment = content[offset + 4:offset + 2 + segment_length]
                if marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
                    fields.extend(parse_tiff_metadata(segment))
                elif marker == 0xFE and segment:
                    fields.append({"tag": "JPEG comment", "value": segment.decode("utf-8", errors="replace")[:500]})
                offset += 2 + segment_length
        else:
            fields.extend(parse_tiff_metadata(content))
    elif suffix == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"):
        offset = 8
        while offset + 12 <= len(content):
            length = int.from_bytes(content[offset:offset + 4], "big")
            kind = content[offset + 4:offset + 8]
            chunk = content[offset + 8:offset + 8 + length]
            if len(chunk) != length: break
            if kind == b"eXIf": fields.extend(parse_tiff_metadata(chunk))
            if kind == b"tEXt" and b"\x00" in chunk:
                key, value = chunk.split(b"\x00", 1)
                fields.append({"tag": key.decode("latin-1", errors="replace")[:80], "value": value.decode("latin-1", errors="replace")[:500]})
            if kind == b"IEND": break
            offset += 12 + length
    elif suffix == ".pdf":
        for tag, key in (("Title", b"Title"), ("Author", b"Author"), ("Subject", b"Subject"), ("Creator", b"Creator"), ("Producer", b"Producer"), ("Creation date", b"CreationDate"), ("Modified date", b"ModDate")):
            match = re.search(rb"/" + key + rb"\s*\(([^)]{1,500})\)", content[:2_000_000])
            if match:
                fields.append({"tag": tag, "value": match.group(1).decode("latin-1", errors="replace")})
    elif suffix == ".docx":
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(content)) as archive:
                if "docProps/core.xml" in archive.namelist() and archive.getinfo("docProps/core.xml").file_size <= 500_000:
                    xml_content = archive.read("docProps/core.xml")
                    root = ET.fromstring(xml_content)
                    labels = {"title": "Title", "subject": "Subject", "creator": "Author", "lastModifiedBy": "Last modified by", "created": "Created", "modified": "Modified", "keywords": "Keywords"}
                    for element in root.iter():
                        key = element.tag.rsplit("}", 1)[-1]
                        if key in labels and element.text:
                            fields.append({"tag": labels[key], "value": element.text[:500]})
        except (OSError, KeyError, zipfile.BadZipFile, ET.ParseError):
            return fields
    return fields[:500]


def inspect_metadata(payload: dict) -> dict:
    if payload.get("authorized") is not True:
        raise LookupError("Confirm that this is your file or that you have permission to inspect it.")
    filename = payload.get("filename")
    encoded = payload.get("content")
    if not isinstance(filename, str) or not isinstance(encoded, str):
        raise LookupError("Choose a local file to inspect.")
    suffix = Path(filename).suffix.lower()
    if suffix not in METADATA_SUFFIXES:
        raise LookupError("Choose a JPEG, PNG, TIFF, PDF, or DOCX file.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LookupError("The selected file data is invalid.") from exc
    if not content or len(content) > MAX_METADATA_BYTES:
        raise LookupError("The file is empty or exceeds the 10 MB limit.")
    fields = parse_file_metadata(content, suffix)
    return {
        "filename": Path(filename).name,
        "queriedAt": now_iso(),
        "source": "uwu-osint local metadata parser",
        "fields": fields,
        "stored": False,
        "notice": "The file was parsed locally and is not saved by the app. This parser recognizes selected fields only; an empty result does not mean the file contains no other metadata. Metadata can include location, author, device, or timestamp details.",
    }


def investigate(value: str, authorized: bool = False, category: str = "all", limit: int = 25, domain_sources=None) -> dict:
    entity = identify(value)
    modules = {}
    if entity["type"] in {"username", "email", "phone"} and not authorized:
        raise LookupError("Confirm this is your account or contact detail, or that you have permission to research it.")
    if entity["type"] == "username":
        modules["accounts"] = run_module(get_account_footprint, entity, authorized, category, limit)
    elif entity["type"] in {"email", "email-domain"}:
        domain_entity = {"type": "domain", "value": entity["domain"]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = pool.submit(run_module, get_dns, entity["domain"])
            registration_future = pool.submit(run_module, get_registration, domain_entity)
            modules["dns"] = dns_future.result()
            modules["registration"] = registration_future.result()
        modules["emailAudit"] = run_module(get_email_audit, entity["domain"], modules["dns"])
    elif entity["type"] == "phone":
        modules["phoneValidation"] = {"status": "ok", **get_phone_validation(entity)}
    elif entity["type"] == "ip":
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = {
                "registration": pool.submit(run_module, get_registration, entity),
                "reverseDns": pool.submit(run_module, get_reverse_dns, entity["value"]),
            }
            for name, future in jobs.items():
                modules[name] = future.result()
    elif entity["type"] == "domain":
        selected_sources = normalize_domain_sources(domain_sources)
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = {
                "dns": pool.submit(run_module, get_dns, entity["value"]),
                "registration": pool.submit(run_module, get_registration, entity),
            }
            if "crtsh" in selected_sources:
                jobs["certificates"] = pool.submit(run_module, get_certificates, entity["value"])
            for name, future in jobs.items():
                modules[name] = future.result()
        if "certificates" not in modules:
            modules["certificates"] = {"status": "skipped", "error": "Not selected for this collection."}
        modules["subdomains"] = run_module(get_subdomain_map, entity["value"], modules["certificates"], selected_sources)
    else:
        modules["registration"] = run_module(get_registration, entity)
    return {"entity": entity, "generatedAt": now_iso(), "modules": modules}


class Handler(BaseHTTPRequestHandler):
    server_version = "uwu-osint/0.1"

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def validate_local_request(self, *, api: bool = False) -> bool:
        raw_host = self.headers.get("Host", "")
        try:
            request_host = urlsplit(f"//{raw_host}")
            request_port = request_host.port
        except ValueError:
            request_host = None
            request_port = None
        valid_hosts = {"127.0.0.1", "localhost", "::1"}
        loopback_host_valid = (
            request_host is not None
            and request_host.hostname is not None
            and request_host.hostname.lower() in valid_hosts
            and not request_host.username
            and not request_host.password
            and request_host.path == ""
            and not request_host.query
            and not request_host.fragment
            and request_port in (None, self.server.server_port)
        )
        public_host = os.environ.get("UWU_OSINT_PUBLIC_HOST", "").strip().lower().rstrip(".")
        public_host_valid = (
            bool(public_host)
            and request_host is not None
            and request_host.hostname is not None
            and request_host.hostname.lower().rstrip(".") == public_host
            and not request_host.username
            and not request_host.password
            and request_host.path == ""
            and not request_host.query
            and not request_host.fragment
            and request_port in (None, 443)
        )
        host_valid = loopback_host_valid or public_host_valid
        if not host_valid:
            self.send_json(403, {"error": "This service does not accept requests for this host."})
            return False
        if api:
            fetch_site = self.headers.get("Sec-Fetch-Site", "").lower()
            origin = self.headers.get("Origin")
            if fetch_site == "cross-site":
                self.send_json(403, {"error": "Cross-site requests to the local API are blocked."})
                return False
            if origin:
                try:
                    parsed_origin = urlsplit(origin)
                    origin_port = parsed_origin.port
                except ValueError:
                    parsed_origin = None
                    origin_port = None
                expected_scheme = "https" if public_host_valid else "http"
                default_port = 443 if expected_scheme == "https" else 80
                expected_port = request_port if request_port is not None else default_port
                origin_default_port = 443 if parsed_origin and parsed_origin.scheme == "https" else 80
                origin_valid = (
                    parsed_origin is not None
                    and parsed_origin.scheme == expected_scheme
                    and parsed_origin.hostname is not None
                    and parsed_origin.hostname.lower() == request_host.hostname.lower()
                    and (origin_port if origin_port is not None else origin_default_port)
                    == expected_port
                    and not parsed_origin.username
                    and not parsed_origin.password
                    and parsed_origin.path == ""
                    and not parsed_origin.query
                    and not parsed_origin.fragment
                )
                if not origin_valid:
                    self.send_json(403, {"error": "The API request origin does not match this local workspace."})
                    return False
        return True

    def do_GET(self):
        if not self.validate_local_request(api=urlsplit(self.path).path.startswith("/api/")):
            return
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_json(200, {"ok": True, "service": "uwu-osint"})
            return
        if path == "/api/tools":
            self.send_json(200, list_open_source_tools())
            return
        if path == "/api/account-categories":
            try:
                query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                category = query.get("category", ["all"])[0]
                self.send_json(200, get_account_preview(category))
            except LookupError as exc:
                self.send_json(503, {"error": str(exc)})
            return
        files = {
            "/": "index.html",
            "/app.js": "app.js",
            "/styles.css": "styles.css",
            "/terms.html": "terms.html",
            "/privacy.html": "privacy.html",
        }
        file_name = files.get(path)
        if not file_name:
            self.send_json(404, {"error": "Not found"})
            return
        file_path = STATIC / file_name
        try:
            content = file_path.read_bytes()
        except OSError:
            self.send_json(404, {"error": "App file not found"})
            return
        content_type = "text/html; charset=utf-8" if file_name.endswith(".html") else (
            "text/javascript; charset=utf-8" if file_name.endswith(".js") else "text/css; charset=utf-8"
        )
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self.validate_local_request(api=True):
            return
        if path not in {"/api/investigate", "/api/metadata"}:
            self.send_json(404, {"error": "Not found"})
            return
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self.send_json(400, {"error": "Invalid request length."})
            return
        body_limit = MAX_METADATA_REQUEST_BYTES if path == "/api/metadata" else MAX_BODY_BYTES
        if length <= 0 or length > body_limit:
            self.send_json(413, {"error": "Request is empty or too large."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Send a JSON request."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise LookupError("The request body must be an object.")
            if path == "/api/investigate":
                if not isinstance(payload.get("query"), str):
                    raise LookupError("Enter a domain or URL, public IP, ASN, @username, email, email-domain:example.com, or international phone number.")
                category = payload.get("category", "all")
                limit = payload.get("limit", 25)
                if not isinstance(category, str) or not isinstance(limit, int) or isinstance(limit, bool):
                    raise LookupError("Invalid account footprint options.")
                result = investigate(
                    payload["query"], payload.get("authorized") is True, category,
                    max(1, min(limit, 40)), payload.get("domainSources"),
                )
            else:
                result = inspect_metadata(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "The request body is not valid JSON."})
            return
        except LookupError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        self.send_json(200, result)

    def log_message(self, fmt, *args):
        # Request targets can contain private query values; keep access logs quiet.
        return


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Cap inbound work so lookups cannot spawn an unlimited worker pool."""

    request_limit = 6

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(self.request_limit)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local uwu-osint research workspace.")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = BoundedThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"uwu-osint is available at http://127.0.0.1:{args.port} (loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping uwu-osint.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
