# uwu-osint

A local-first workspace for authorized research on public internet infrastructure and self-audits of your own public accounts. Results are grouped into cases with collection timestamps and source links.

## Features

- **Domain footprint:** DNS records, RDAP registration, certificate transparency names, passive hostname discovery, and public A/AAAA resolution for a bounded set of discovered hosts.
- **IP and ASN records:** registration and network allocation details from RDAP services selected through IANA bootstrap data. Only globally routable public IP addresses are accepted.
- **Account footprint:** check a username you own or are authorized to audit against up to 25 public profile URLs. Results are marked as possible matches, not proof of identity or account ownership.
- **Local metadata inspection:** parse common JPEG, PNG, TIFF, PDF, and DOCX metadata. Files are sent only to the loopback app server, parsed in memory, and not saved.
- **Report workspace:** import JSON, JSONL, and CSV reports in the browser. The importer keeps only in-scope hostnames and IP addresses and drops person, contact, and credential fields.
- **External source shortcuts:** launch single authorized searches in AlienVault OTX, OpenCorporates, and Academic Torrents. Epieos opens for a manual email search without the app submitting the address. Results remain on the provider's site and are not collected by the app.
- **Case notebook:** cases and notes stay in browser local storage. Export a case to JSON when you need a portable copy.

Each collection source runs independently; one unavailable provider does not discard successful results from the others. Domain research queries public data providers and DNS over HTTPS rather than scanning infrastructure. Account checks request the selected public profile URLs. The app does not scan ports, brute-force names, or log in to or message accounts.

Use this software only for assets and accounts you own or have permission to audit. Follow provider terms and rate limits. Public records can be incomplete, stale, or ambiguous.

## Run locally

Requires Python 3.10 or newer. The server uses only the Python standard library and does not need API keys.

```sh
python3 server.py
```

Open <http://127.0.0.1:8080>. To choose another port, run `python3 server.py --port 8787`.

The server binds to loopback (`127.0.0.1`), so it is intended for local use.

## External source searches

Open **Built-in modules → Search external sources**, enter a query, confirm authorization, then choose one provider. Each click opens one provider page in a new tab. Epieos requires an email address, but the app opens its site without submitting that address; run the search manually there. Other providers receive the query in their search URL. Results are not saved by uwu-osint.

## Data sources

- [Cloudflare DNS over HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) for DNS answers and public hostname resolution.
- [IANA RDAP bootstrap registries](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml) for selecting registration data services.
- [Certificate Search](https://crt.sh/) for public certificate names.
- [HackerTarget Host Search](https://hackertarget.com/ip-tools/) for passive host and address results. Availability and limits are controlled by the provider.
- [WhatsMyName public profile definitions](https://github.com/WebBreacher/WhatsMyName) provide the live profile-check rules. Those definitions are published under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); they are fetched when needed and are not bundled in this repository.

## Privacy

The Python server keeps no database and does not log query values. Search subjects are sent to the selected public providers. Epieos is an exception: the app opens its site, and you submit any email search there yourself. Username checks query the profile sites listed by the live definitions. Cases and notes are held in browser local storage until you delete them or clear site data. Metadata inspection results remain in memory and are not included in saved cases. Do not enter secrets or private personal data.
