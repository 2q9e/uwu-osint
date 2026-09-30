# uwu-osint

A local-first workspace for authorized research on public internet infrastructure and self-audits of your own public accounts. Results are grouped into cases with collection timestamps and source links.

## Features

- **Domain footprint:** DNS and DNSSEC response details, RDAP registration, selectable crt.sh and HackerTarget passive sources, and an optional Common Crawl URL-index search for historical host observations. Archived dates are kept separate from collection time. Public A/AAAA resolution is bounded to discovered hosts. Each provider reports its own outcome; successful findings remain visible when another provider fails. Special-use and common internal suffixes are blocked before public queries.
- **Email domain audit:** validate a standard email shape, then inspect only its domain’s MX, SPF, and DMARC DNS records plus RDAP registration. Or use `email-domain:example.com` to audit a domain without entering or storing a mailbox identifier. SPF/DMARC statuses report matching-record presence and duplicate ambiguity, not complete policy validity. Mailbox existence and owner identity are not checked.
- **Phone format check:** normalize international phone numbers to E.164 syntax locally. The app does not look up subscriber identity, carrier, location, or account data.
- **URL, IP, and ASN intake:** accept HTTP(S) URLs by extracting their hostname, as well as globally routable IPv4/IPv6 addresses and ASN values.
- **IP and ASN records:** registration and network allocation details from RDAP services selected through IANA bootstrap data. Only globally routable public IP addresses are accepted.
- **Account footprint:** check a username you own or are authorized to audit against up to 25 public profile URLs. Results are marked as possible matches, not proof of identity or account ownership.
- **Local metadata inspection:** recognize selected JPEG, PNG, TIFF, PDF, and DOCX metadata fields. Files are sent only to the loopback app server, parsed in memory, and not saved. An empty result means this parser found no supported fields; it does not prove the file has no metadata.
- **Report workspace:** import JSON, JSONL, CSV, and plain hostname-list reports in the browser, including compatible Subfinder, theHarvester, Amass, and SpiderFoot output. The importer keeps only in-scope hostnames and IP addresses, drops person/contact/credential fields, merges duplicate findings while preserving source labels, and records the filename, input count, invalid lines, duplicates, and row or finding caps. It does not launch those tools.
- **Infrastructure relationship graph:** view DNS, certificate, hostname, reverse-DNS, and RDAP observations for the selected domain, email-domain-only, IP, or ASN case. Filter by source, entity type, or label; select a node to review its linked evidence. Its timeline separates provider-reported event dates from the time the app collected them. The graph is not an ownership or identity verdict. Export source, event, and collection fields as GraphML for compatible tools. It uses saved case data only and makes no new provider requests.
- **Research source guide:** search and filter open-source tools, public directories, and specialist providers by capability, category, and access model. Cards summarize typical inputs, outputs, and access gates while distinguishing external products from built-in modules; verify current terms and pricing at each provider.
- **External source shortcuts:** launch single authorized searches in AlienVault OTX, OpenCorporates, and Academic Torrents. Epieos opens for a manual email or phone search without the app submitting the value. Results remain on the provider's site and are not collected by the app.
- **Case notebook:** cases and notes stay in browser local storage. Refresh history keeps up to five summaries and provider-specific hostname snapshots per case. It compares only providers that succeeded with complete results in both runs; “not returned” is not treated as proof that a hostname disappeared. Export a case to JSON when you need a portable copy, or clear saved cases and notes from the workspace controls.

Each collection source runs independently; one unavailable provider does not discard successful results from the others. Domain research queries public data providers and DNS over HTTPS rather than scanning infrastructure. Account checks request the selected public profile URLs. The app does not scan ports, brute-force names, or log in to or message accounts.

Use this software only for assets and accounts you own or have permission to audit. Follow provider terms and rate limits. Public records can be incomplete, stale, or ambiguous.

## Lookup formats

- Domain or URL: `iana.org` or `https://iana.org/path` (URL paths are ignored; the host is researched). Special-use names such as `example.com` are rejected.
- Public network: `8.8.8.8`, `2001:4860:4860::8888`, or `AS15169`.
- Username: `@handle` or `username:handle`.
- Email: `name@iana.org` or `email:name@iana.org` (address stored in the local case; domain DNS only).
- Email-domain audit: `email-domain:iana.org` (domain only; no mailbox identifier is stored).
- Phone: `+14165550123` or `phone:+1 (416) 555-0123` (local syntax check only).

## Run locally

Requires Python 3.10 or newer. The server uses only the Python standard library and does not need API keys.

```sh
python3 server.py
```

Open <http://127.0.0.1:8080>. To choose another port, run `python3 server.py --port 8787`.

The server binds to loopback (`127.0.0.1`), accepts only loopback Host headers, rejects cross-origin API requests, caps concurrent requests, and uses connection timeouts. It is intended for local use.

## External source searches

Open **Built-in modules → Search external sources**, enter a query, confirm authorization, then choose one provider. Each click opens one provider page in a new tab. Epieos accepts a manually entered email or international phone search; the app opens its site without submitting the value. Other providers receive the query in their search URL. OTX URL lookups send the complete URL; the app rejects embedded credentials and requires a separate confirmation when the URL has a path, query, or fragment. Remove tokens and private data first. Results are not saved by uwu-osint.

The **Research source guide** lists open-source tools, third-party directories, and providers with links to their public details. It does not connect to those services or send a case subject. Its access notes are summaries; check the provider for current plan and licensing terms.

## Data sources

- [Cloudflare DNS over HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) for DNS answers and public hostname resolution.
- [IANA special-use domain registry](https://www.iana.org/assignments/special-use-domain-names) defines names that are not intended for ordinary public DNS lookups.
- [IANA RDAP bootstrap registries](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml) for selecting registration data services.
- [Certificate Search](https://crt.sh/) for public certificate names.
- [HackerTarget Host Search](https://hackertarget.com/ip-tools/) for passive host and address results. Availability and limits are controlled by the provider.
- [Common Crawl URL Index](https://index.commoncrawl.org/) for a bounded search of the latest public web crawl index. Returned capture timestamps describe archived observations and do not indicate current host availability.
- [WhatsMyName public profile definitions](https://github.com/WebBreacher/WhatsMyName/blob/062bcfe48df79fa618e96edc79dc9673f3fe5643/wmn-data.json) provide username profile-check rules pinned to revision `062bcfe48df79fa618e96edc79dc9673f3fe5643`. They are fetched when needed, not bundled, and do not receive the username during the catalog request. The definitions are published under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

## Privacy

The Python server keeps no database and does not log request targets or query values. Domain searches send the hostname to DNS and RDAP providers plus the passive sources you select; Common Crawl is optional and queries its current URL index for archived public pages. Email-domain lookups send only the domain to public DNS and RDAP sources; phone validation runs locally with no network request. Search subjects are sent to other selected public providers only when you launch those searches. Epieos is manual: the app opens its site without submitting an email address or phone number. Before a username check, the app displays the selected profile site names and hostnames from a pinned catalog revision; the username is sent to those profile sites. Cases and notes are held in browser local storage until you delete them, use **Clear saved cases**, or clear site data. Email addresses, phone numbers, imported filenames, and notes in cases may be sensitive; exports include case subjects and saved import filenames. Metadata inspection results remain in memory and are not included in saved cases. Do not enter secrets or private personal data.
