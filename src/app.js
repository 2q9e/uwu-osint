const STORAGE_KEY = "uwu-osint-cases-v1";
const ROOT = document.querySelector("#app");

function readCases() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.filter((item) => item && item.id && item.result) : [];
  } catch {
    return [];
  }
}

const state = {
  cases: readCases(),
  selectedCaseId: null,
  tab: "overview",
  busy: false,
  flash: "",
  view: "workspace",
  accountCategories: [],
  categoriesLoading: false,
  accountCategory: "all",
  metadataBusy: false,
  metadataResult: null,
};

state.selectedCaseId = state.cases[0]?.id ?? null;

function currentCase() {
  return state.cases.find((item) => item.id === state.selectedCaseId) ?? null;
}

function persistCases() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.cases));
  } catch {
    state.flash = "Browser storage is full. Export this case before leaving the page.";
  }
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function shortDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function countDns(dns) {
  if (!dns?.records) return 0;
  return Object.values(dns.records).reduce((total, rows) => total + (Array.isArray(rows) ? rows.length : 0), 0);
}

function statusBadge(module, label) {
  const status = module?.status === "ok" ? "available" : "unavailable";
  const text = module?.status === "ok" ? label : "Unavailable";
  return `<span class="status-badge ${status}"><i></i>${esc(text)}</span>`;
}

function safeLink(url, label = "Open source") {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return "";
    return `<a class="source-link" href="${esc(parsed.href)}" target="_blank" rel="noopener noreferrer">${esc(label)} <span aria-hidden="true">↗</span></a>`;
  } catch {
    return "";
  }
}

function sourcesFor(result) {
  const modules = result?.modules ?? {};
  const sources = [];
  if (modules.dns) sources.push({ title: "DNS over HTTPS", name: "Cloudflare", module: modules.dns, icon: "⌁" });
  if (modules.certificates) sources.push({ title: "Certificate transparency", name: "crt.sh", module: modules.certificates, icon: "▤" });
  if (modules.registration) sources.push({ title: "Registration data", name: "IANA RDAP", module: modules.registration, icon: "◈" });
  if (modules.subdomains) {
    for (const provider of modules.subdomains.providers || []) {
      sources.push({
        title: provider.name,
        name: provider.name,
        module: { ...modules.subdomains, status: provider.status, source: provider.source },
        icon: provider.name.includes("Certificate") ? "▤" : "⌘",
      });
    }
  }
  if (modules.accounts) sources.push({ title: "Public profile checks", name: "Profile definitions", module: modules.accounts, icon: "◎" });
  return sources;
}

function sourceUrl(source) {
  if (source.module?.source) return source.module.source;
  if (source.name === "IANA RDAP") return "https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml";
  if (source.name === "Cloudflare") return "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/";
  return "https://crt.sh/";
}

function sourceCards(result) {
  const sources = sourcesFor(result);
  if (!sources.length) return "";
  return `<section class="source-grid" aria-label="Data sources">${sources.map((source) => `
    <article class="source-card">
      <div class="source-card-top"><span class="source-symbol">${esc(source.icon)}</span>${statusBadge(source.module, "Collected")}</div>
      <div class="source-name">${esc(source.name)}</div>
      <div class="source-description">${esc(source.title)}</div>
      <div class="source-card-bottom"><span>${esc(shortDate(source.module?.queriedAt))}</span>${safeLink(sourceUrl(source), "View source")}</div>
    </article>`).join("")}</section>`;
}

function dnsSummary(dns) {
  return Object.entries(dns?.records ?? {}).map(([type, rows]) => ({ type, count: rows.length }))
    .filter((row) => row.count > 0)
    .map((row) => `<span class="mini-pill"><b>${esc(row.type)}</b> ${row.count}</span>`).join("") || `<span class="muted">No records returned</span>`;
}

function overviewContent(record) {
  const result = record.result;
  const modules = result.modules ?? {};
  if (result.entity?.type === "username") return accountOverview(record);
  const domain = result.entity?.type === "domain";
  const certCount = modules.certificates?.names?.length ?? 0;
  const hostCount = modules.subdomains?.totalFound ?? 0;
  const dnsCount = countDns(modules.dns);
  const registration = modules.registration;
  const registrationName = registration?.name || registration?.networkType || registration?.handle || "No registration name returned";

  return `
    <div class="metrics-grid">
      <article class="metric-card"><span class="metric-label">DNS answers</span><strong>${dnsCount}</strong><span class="metric-foot">Across ${Object.keys(modules.dns?.records ?? {}).length} record types</span></article>
      <article class="metric-card"><span class="metric-label">Certificate names</span><strong>${domain ? certCount : "—"}</strong><span class="metric-foot">From public certificate logs</span></article>
      <article class="metric-card"><span class="metric-label">Registration</span><strong class="metric-word">${esc(registration?.status === "ok" ? "Found" : registration?.status === "error" ? "Unavailable" : "Pending")}</strong><span class="metric-foot">${esc(registrationName)}</span></article>
      <article class="metric-card"><span class="metric-label">Updated</span><strong class="metric-time">${esc(shortDate(result.generatedAt))}</strong><span class="metric-foot">Latest collection run</span></article>
    </div>
    <section class="overview-grid">
      <article class="panel overview-panel">
        <div class="panel-heading"><div><span class="eyebrow">01 / NETWORK RECORDS</span><h3>DNS snapshot</h3></div><button class="text-button" data-tab="dns">View details <span>→</span></button></div>
        ${modules.dns?.status === "ok" ? `<div class="pill-row">${dnsSummary(modules.dns)}</div>` : `<div class="inline-error">${esc(modules.dns?.error || "DNS collection was not run for this subject.")}</div>`}
        ${modules.dns?.errors?.length ? `<div class="subtle-note">${esc(modules.dns.errors.length)} record type(s) could not be retrieved.</div>` : ""}
      </article>
      <article class="panel overview-panel">
        <div class="panel-heading"><div><span class="eyebrow">02 / CERTIFICATE LOGS</span><h3>Observed names</h3></div>${domain ? `<button class="text-button" data-tab="certificates">View details <span>→</span></button>` : ""}</div>
        ${domain ? (modules.certificates?.status === "ok" ? `<div class="summary-number">${certCount}<span> certificate name${certCount === 1 ? "" : "s"}</span></div><div class="subtle-note">Names in public certificate transparency records.</div>` : `<div class="inline-error">${esc(modules.certificates?.error || "Certificate lookup was not available.")}</div>`) : `<div class="subtle-note">Certificate discovery is available for domain cases.</div>`}
      </article>
      ${domain ? `<article class="panel overview-panel">
        <div class="panel-heading"><div><span class="eyebrow">03 / PASSIVE HOST DISCOVERY</span><h3>Subdomain map</h3></div><button class="text-button" data-tab="subdomains">View map <span>→</span></button></div>
        ${modules.subdomains?.status === "ok" ? `<div class="summary-number">${hostCount}<span> scoped host${hostCount === 1 ? "" : "s"}</span></div><div class="subtle-note">${esc(modules.subdomains.resolvedCount ?? 0)} hosts resolved to public addresses.</div>` : `<div class="inline-error">${esc(modules.subdomains?.error || "No passive host data returned.")}</div>`}
      </article>` : ""}
      <article class="panel overview-panel registration-panel">
        <div class="panel-heading"><div><span class="eyebrow">${domain ? "04" : "03"} / REGISTRY RECORD</span><h3>Registration</h3></div>${registration?.source ? safeLink(registration.source, "RDAP record") : ""}</div>
        ${registration?.status === "ok" ? registrationPreview(registration, result.entity?.type) : `<div class="inline-error">${esc(registration?.error || "Registration lookup is not available.")}</div>`}
      </article>
    </section>
    <section class="panel sources-panel">
      <div class="panel-heading"><div><span class="eyebrow">COLLECTION PROVENANCE</span><h3>Sources & timestamps</h3></div><span class="panel-caption">Every result is attributable</span></div>
      ${sourceCards(result)}
    </section>
    ${notesPanel(record)}
  `;
}

function accountOverview(record) {
  const account = record.result.modules?.accounts;
  const sites = account?.sites || [];
  return `<div class="metrics-grid">
      <article class="metric-card"><span class="metric-label">Profiles checked</span><strong>${esc(account?.checked ?? 0)}</strong><span class="metric-foot">Bounded public URL checks</span></article>
      <article class="metric-card"><span class="metric-label">Possible matches</span><strong>${esc(account?.found ?? 0)}</strong><span class="metric-foot">Requires manual verification</span></article>
      <article class="metric-card"><span class="metric-label">Not found</span><strong>${esc(account?.notFound ?? 0)}</strong><span class="metric-foot">Based on site response rules</span></article>
      <article class="metric-card"><span class="metric-label">Updated</span><strong class="metric-time">${esc(shortDate(record.result.generatedAt))}</strong><span class="metric-foot">Latest collection run</span></article>
    </div>
    ${account?.status === "error" ? `<div class="notice warning-notice">${esc(account.error)}</div>` : ""}
    <section class="panel overview-panel account-summary"><div class="panel-heading"><div><span class="eyebrow">ACCOUNT FOOTPRINT</span><h3>Public profile candidates</h3></div><button class="text-button" data-tab="accounts">View checks <span>→</span></button></div>
      <p class="account-disclaimer">${esc(account?.notice || "A profile URL match is only a lead. It does not verify identity or account ownership.")}</p>
      ${sites.filter((item) => item.status === "found").length ? `<div class="account-chips">${sites.filter((item) => item.status === "found").slice(0, 12).map((item) => `<span class="mini-pill">${esc(item.site)}</span>`).join("")}</div>` : `<div class="subtle-note">No profile candidates have been returned yet.</div>`}
    </section>
    ${sourceCards(record.result)}${notesPanel(record)}`;
}

function registrationPreview(registration, entityType) {
  const pairs = [];
  if (registration.name) pairs.push(["Name", registration.name]);
  if (registration.handle) pairs.push(["Handle", registration.handle]);
  if (registration.country) pairs.push(["Country", registration.country]);
  if (registration.networkType) pairs.push(["Network type", registration.networkType]);
  if (registration.startAddress && registration.endAddress) pairs.push(["Address range", `${registration.startAddress} – ${registration.endAddress}`]);
  if (registration.startAutnum != null) pairs.push(["ASN range", `AS${registration.startAutnum} – AS${registration.endAutnum}`]);
  if (entityType === "domain" && registration.nameservers?.length) pairs.push(["Name servers", registration.nameservers.slice(0, 2).join(", ")]);
  return `<div class="detail-list">${pairs.slice(0, 4).map(([key, value]) => `<div class="detail-row"><span>${esc(key)}</span><b>${esc(value)}</b></div>`).join("") || `<div class="subtle-note">The registry returned a record with no summary fields.</div>`}</div>`;
}

function notesPanel(record) {
  return `<section class="panel notes-panel"><div class="panel-heading"><div><span class="eyebrow">CASE NOTEBOOK</span><h3>Working notes</h3></div><span class="saved-label">Saved in this browser</span></div><textarea data-notes placeholder="Add context, hypotheses, or follow-up questions. These notes stay in local browser storage." rows="3">${esc(record.notes || "")}</textarea></section>`;
}

function dnsContent(record) {
  const module = record.result.modules?.dns;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">⌁</span><h3>No DNS collection</h3><p>DNS lookups are available when the subject is a domain.</p></div>`;
  if (module.status !== "ok") return `<div class="empty-panel"><span class="empty-glyph">⌁</span><h3>DNS data unavailable</h3><p>${esc(module.error)}</p>${safeLink(module.source || "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "Source documentation")}</div>`;
  const groups = Object.entries(module.records ?? {});
  return `<div class="tab-intro"><div><span class="eyebrow">LIVE PUBLIC DNS ANSWERS</span><h2>DNS records</h2><p>Query time ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Provider details")}</div>
    ${module.errors?.length ? `<div class="notice warning-notice">${esc(module.errors.join(" · "))}</div>` : ""}
    <div class="record-grid">${groups.map(([type, rows]) => `<section class="panel record-panel"><div class="record-heading"><div><span class="record-type">${esc(type)}</span><h3>${esc(recordTypeName(type))}</h3></div><span class="count-tag">${rows.length}</span></div>
      ${rows.length ? `<ul class="record-list">${rows.map((item) => `<li><code>${esc(item.data)}</code>${item.ttl != null ? `<span>TTL ${esc(item.ttl)}s</span>` : ""}</li>`).join("")}</ul>` : `<div class="empty-record">No answer returned</div>`}
    </section>`).join("")}</div>
    ${sourceCards({ modules: { dns: module } })}`;
}

function recordTypeName(type) {
  return ({ A: "IPv4 addresses", AAAA: "IPv6 addresses", CNAME: "Aliases", MX: "Mail exchangers", NS: "Name servers", TXT: "Text records", CAA: "Certificate authorities" })[type] || type;
}

function certificatesContent(record) {
  const module = record.result.modules?.certificates;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">▤</span><h3>No certificate collection</h3><p>Certificate transparency lookup is available for domain cases.</p></div>`;
  if (module.status !== "ok") return `<div class="empty-panel"><span class="empty-glyph">▤</span><h3>Certificate data unavailable</h3><p>${esc(module.error)}</p>${safeLink("https://crt.sh/", "Open crt.sh")}</div>`;
  const names = module.names ?? [];
  return `<div class="tab-intro"><div><span class="eyebrow">PUBLIC CERTIFICATE TRANSPARENCY</span><h2>Observed names</h2><p>${names.length} distinct name${names.length === 1 ? "" : "s"} · checked ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Open source query")}</div>
    ${module.truncated ? `<div class="notice">Showing the first 2,000 distinct names from this response.</div>` : ""}
    ${names.length ? `<div class="panel table-panel"><table><thead><tr><th>DNS name</th><th>Wildcard</th><th>Certificate logged</th></tr></thead><tbody>${names.map((item) => `<tr><td><code>${esc(item.name)}</code></td><td>${item.wildcard ? `<span class="tag">Wildcard</span>` : "—"}</td><td>${esc(shortDate(item.firstSeen))}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty-panel compact-empty"><h3>No names returned</h3><p>The source did not return matching certificate names for this query.</p></div>`}
    ${sourceCards({ modules: { certificates: module } })}`;
}

function registrationContent(record) {
  const module = record.result.modules?.registration;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">◈</span><h3>No registration collection</h3><p>Registration data was not available for this case.</p></div>`;
  if (module.status !== "ok") return `<div class="empty-panel"><span class="empty-glyph">◈</span><h3>Registration data unavailable</h3><p>${esc(module.error)}</p>${safeLink("https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml", "IANA RDAP registry")}</div>`;
  const type = record.result.entity?.type;
  const rows = [
    ["Registry name", module.name], ["Handle", module.handle], ["Country", module.country],
    ["Network type", module.networkType], ["Start address", module.startAddress], ["End address", module.endAddress],
    ["CIDR", module.cidrs?.join(", ")], ["ASN range", module.startAutnum != null ? `AS${module.startAutnum} – AS${module.endAutnum}` : null],
    ["Status", module.status?.join(", ")], ["Name servers", module.nameservers?.join(", ")],
  ].filter(([, value]) => value != null && value !== "");
  const events = module.events ?? [];
  return `<div class="tab-intro"><div><span class="eyebrow">AUTHORITATIVE REGISTRY RESPONSE</span><h2>${type === "domain" ? "Domain" : type === "asn" ? "ASN" : "Network"} registration</h2><p>Retrieved ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Open RDAP record")}</div>
    <section class="panel registration-details"><div class="detail-list">${rows.map(([key, value]) => `<div class="detail-row"><span>${esc(key)}</span><b>${esc(value)}</b></div>`).join("") || `<div class="subtle-note">No public summary fields were returned.</div>`}</div></section>
    <section class="panel events-panel"><div class="panel-heading"><div><span class="eyebrow">REGISTRY HISTORY</span><h3>Events</h3></div><span class="panel-caption">${events.length} record${events.length === 1 ? "" : "s"}</span></div>${events.length ? `<div class="event-list">${events.map((event) => `<div class="event-row"><span class="event-dot"></span><b>${esc(event.action)}</b><time>${esc(shortDate(event.date))}</time></div>`).join("")}</div>` : `<div class="empty-record">No dated events returned.</div>`}</section>
    ${sourceCards({ modules: { registration: module } })}`;
}

function networkGraph(module, domain) {
  const hosts = (module?.hosts || []).slice(0, 18);
  if (!hosts.length) return `<div class="empty-panel compact-empty"><h3>No scoped hosts to map</h3><p>Try again later if public sources were unavailable.</p></div>`;
  const rowHeight = 35;
  const height = Math.max(130, hosts.length * rowHeight + 34);
  const rootY = height / 2;
  const lines = hosts.map((host, index) => {
    const y = 22 + index * rowHeight;
    const addresses = (host.addresses || []).slice(0, 2).join(", ") || "unresolved";
    const graphName = host.name.length > 68 ? `${host.name.slice(0, 65)}…` : host.name;
    const graphAddresses = addresses.length > 68 ? `${addresses.slice(0, 65)}…` : addresses;
    return `<path class="graph-edge" d="M 142 ${rootY} C 210 ${rootY}, 220 ${y + 4}, 288 ${y + 4}"/><circle class="graph-node" cx="288" cy="${y + 4}" r="4"/><text class="graph-host" x="302" y="${y + 1}"><title>${esc(host.name)}</title>${esc(graphName)}</text><text class="graph-ip" x="302" y="${y + 14}">${esc(graphAddresses)}</text>`;
  }).join("");
  return `<div class="network-graph-wrap"><svg class="network-graph" viewBox="0 0 760 ${height}" role="img" aria-label="Relationship map of ${esc(domain)} and its discovered hosts"><path class="graph-root-edge" d="M 106 ${rootY} H 142"/><rect class="graph-root" x="18" y="${rootY - 18}" width="124" height="36" rx="8"/><text class="graph-root-label" x="80" y="${rootY + 4}" text-anchor="middle">${esc(domain)}</text>${lines}</svg></div>`;
}

function subdomainsContent(record) {
  const module = record.result.modules?.subdomains;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">⌘</span><h3>No host discovery run</h3><p>Passive hostname discovery is available for domain cases.</p></div>`;
  if (module.status !== "ok") return `<div class="empty-panel"><span class="empty-glyph">⌘</span><h3>Host discovery unavailable</h3><p>${esc(module.error || "No public source returned results.")}</p></div>`;
  const hosts = module.hosts || [];
  return `<div class="tab-intro"><div><span class="eyebrow">PASSIVE DOMAIN FOOTPRINT</span><h2>Subdomain map</h2><p>${esc(module.totalFound ?? hosts.length)} scoped hosts · checked ${esc(shortDate(module.queriedAt))}</p></div></div>
    ${module.truncated ? `<div class="notice">At least one public source was capped, or more than 500 names were found. This case may contain a partial result set.</div>` : ""}
    <section class="panel graph-panel"><div class="panel-heading"><div><span class="eyebrow">CORRELATED HOSTS</span><h3>${esc(record.result.entity?.value)}</h3></div><span class="panel-caption">First 18 hosts shown in graph</span></div>${networkGraph(module, record.result.entity?.value)}</section>
    <div class="panel table-panel host-table"><table><thead><tr><th>Hostname</th><th>Public addresses</th><th>Sources</th></tr></thead><tbody>${hosts.map((host) => `<tr><td><code>${esc(host.name)}</code></td><td>${host.addresses?.length ? host.addresses.map((address) => `<code>${esc(address)}</code>`).join("<br />") : `<span class="muted">${host.resolutionAttempted ? "Unresolved" : "Not checked (limit 25)"}</span>`}</td><td>${(host.sources || []).map((source) => `<span class="tag">${esc(source)}</span>`).join(" ")}</td></tr>`).join("") || `<tr><td colspan="3">No hostnames returned.</td></tr>`}</tbody></table></div>
    ${(module.providers || []).map((provider) => provider.status === "error" ? `<div class="notice warning-notice">${esc(provider.name)}: ${esc(provider.error || "Source unavailable.")}</div>` : "").join("")}
    ${sourceCards({ modules: { subdomains: module } })}`;
}

function accountsContent(record) {
  const module = record.result.modules?.accounts;
  if (!module || module.status === "error") return `<div class="empty-panel"><span class="empty-glyph">◎</span><h3>Account checks unavailable</h3><p>${esc(module?.error || "The profile check did not return results.")}</p></div>`;
  const sites = module.sites || [];
  const rows = sites.map((item) => `<tr><td>${esc(item.site)}</td><td><span class="tag">${esc(item.category)}</span></td><td><span class="account-status ${esc(item.status)}">${esc(item.status.replace("_", " "))}</span></td><td>${item.url ? safeLink(item.url, "Open profile") : "—"}</td></tr>`).join("");
  return `<div class="tab-intro"><div><span class="eyebrow">SELF-AUDIT / PUBLIC PROFILE URLS</span><h2>Account footprint</h2><p>@${esc(module.handle)} · ${esc(module.checked)} bounded checks · ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Profile rules and license")}</div>
    <div class="metrics-grid account-metrics"><article class="metric-card"><span class="metric-label">Possible matches</span><strong>${esc(module.found)}</strong><span class="metric-foot">Review these manually</span></article><article class="metric-card"><span class="metric-label">Not found</span><strong>${esc(module.notFound)}</strong><span class="metric-foot">Site-specific response rules</span></article><article class="metric-card"><span class="metric-label">Unknown</span><strong>${esc(module.unknown)}</strong><span class="metric-foot">Blocked or ambiguous responses</span></article><article class="metric-card"><span class="metric-label">Rule license</span><strong class="metric-word">${esc(module.license)}</strong><span class="metric-foot">Live source data</span></article></div>
    <div class="notice warning-notice">${esc(module.notice)}</div>
    <div class="panel table-panel"><table><thead><tr><th>Site</th><th>Category</th><th>Result</th><th>Profile</th></tr></thead><tbody>${rows || `<tr><td colspan="4">No sites were checked.</td></tr>`}</tbody></table></div>
    ${sourceCards({ modules: { accounts: module } })}`;
}

function importedContent(record) {
  const modules = record.result.modules?.imports ?? [];
  return `<div class="tab-intro"><div><span class="eyebrow">REPORT INTERCHANGE</span><h2>Imported tool results</h2><p>Common JSON, JSONL, or CSV reports · personal and contact fields are discarded during import.</p></div></div>
    <section class="panel import-panel"><div class="panel-heading"><div><span class="eyebrow">ADD EXISTING EVIDENCE</span><h3>Import an infrastructure report</h3></div><span class="panel-caption">Stored only with this browser case</span></div><div class="import-controls"><select id="import-tool"><option value="Generic OSINT report">Generic OSINT report</option><option value="Domain report">Domain report</option><option value="Network inventory">Network inventory</option><option value="Certificate report">Certificate report</option></select><label class="file-picker">Choose report<input id="report-file" type="file" accept=".json,.jsonl,.csv,application/json,text/csv" /></label><button class="secondary-button" data-action="import-report">Import to case</button></div><p class="import-footnote">In-scope hostnames and IP addresses are kept. Email addresses, names, phone numbers, and unrelated values are dropped. Maximum file size: 4 MB.</p></section>
    ${modules.length ? `<div class="import-list">${modules.map((item) => `<section class="panel imported-report"><div class="imported-report-heading"><div><span class="tag">${esc(item.tool)}</span><b>${item.findings.length} finding${item.findings.length === 1 ? "" : "s"}</b></div><span>${esc(shortDate(item.queriedAt))}</span></div>${item.findings.length ? `<ul>${item.findings.slice(0, 500).map((finding) => `<li><span class="tag">${esc(finding.type)}</span><code>${esc(finding.value)}</code></li>`).join("")}</ul>` : `<p class="subtle-note">No in-scope hostname or IP findings were found in that report.</p>`}</section>`).join("")}</div>` : `<div class="empty-panel compact-empty"><h3>No imported reports yet</h3><p>Import JSON, JSONL, or CSV infrastructure output to add scoped findings to this case.</p></div>`}`;
}

function toolsDirectory() {
  const cards = [
    { title: "Domain footprint", category: "PUBLIC INFRASTRUCTURE", detail: "Join DNS answers, registry data, certificate names, and passive hostname results into one scoped view.", icon: "⌘" },
    { title: "Account footprint", category: "SELF-AUDIT", detail: "Check a username you own across a bounded set of public profile URLs. Matches are candidates, not identity proof.", icon: "◎" },
    { title: "File metadata", category: "LOCAL INSPECTION", detail: "Read common image, PDF, and Office metadata on this machine, including GPS and author fields.", icon: "▧" },
    { title: "Report workspace", category: "INTERCHANGE", detail: "Import common infrastructure reports, filter to the case scope, and discard personal and contact data.", icon: "⇧" },
  ];
  return `<section class="tool-intro"><div><span class="eyebrow">NATIVE RESEARCH MODULES</span><h2>One workspace for public signals.</h2><p>Each module works with bounded collection, source attribution, and results kept in the local case workspace.</p></div><div class="tool-count"><strong>${cards.length}</strong><span>built-in modules</span></div></section>
    <section class="tool-card-grid">${cards.map((card) => `<article class="panel integration-card"><div class="integration-top"><span class="integration-icon">${card.icon}</span><span class="integration-status ready"><i></i>READY</span></div><span class="eyebrow">${card.category}</span><h3>${card.title}</h3><p>${card.detail}</p><div class="integration-footer"><span>Built in</span></div></article>`).join("")}</section>
    <section class="panel tool-workbench"><div class="panel-heading"><div><span class="eyebrow">LOCAL FILE PRIVACY CHECK</span><h3>Inspect file metadata</h3></div><span class="panel-caption">JPEG · PNG · TIFF · PDF · DOCX</span></div>
      <p class="tool-copy">Choose a file you own or have permission to inspect. It is sent only to this machine's local app server, parsed in memory, and not saved.</p>
      <div class="file-audit-controls"><label class="file-picker">Choose local file<input id="metadata-file" type="file" accept=".jpg,.jpeg,.png,.tif,.tiff,.pdf,.docx,image/jpeg,image/png,image/tiff,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" /></label><label class="scope-check-inline"><input type="checkbox" id="metadata-scope" /><span class="custom-check"></span><span>This is my file or I have permission</span></label><button class="secondary-button" data-action="audit-metadata" ${state.metadataBusy ? "disabled" : ""}>${state.metadataBusy ? "Inspecting…" : "Inspect metadata"}</button></div>
      ${state.metadataResult ? metadataResults(state.metadataResult) : ""}
    </section>
    ${state.flash ? `<div class="flash-message" role="status">${esc(state.flash)}</div>` : ""}`;
}

function metadataResults(result) {
  return `<div class="metadata-result"><div class="metadata-result-head"><div><span class="eyebrow">LOCAL FILE RESULT</span><b>${esc(result.filename)}</b><small>${result.fields.length} metadata field${result.fields.length === 1 ? "" : "s"} · ${esc(shortDate(result.queriedAt))}</small></div><span class="status-badge available"><i></i>Not saved</span></div><div class="metadata-fields">${result.fields.map((field) => `<div class="detail-row"><span>${esc(field.tag)}</span><b>${esc(Array.isArray(field.value) ? field.value.join(", ") : field.value)}</b></div>`).join("") || `<span class="subtle-note">No readable metadata fields found.</span>`}</div><p class="import-footnote">${esc(result.notice)}</p></div>`;
}

function contentFor(record) {
  if (state.tab === "accounts") return accountsContent(record);
  if (state.tab === "subdomains") return subdomainsContent(record);
  if (state.tab === "dns") return dnsContent(record);
  if (state.tab === "certificates") return certificatesContent(record);
  if (state.tab === "registration") return registrationContent(record);
  if (state.tab === "imports") return importedContent(record);
  return overviewContent(record);
}

function caseList() {
  if (!state.cases.length) return `<div class="case-list-empty">Your saved cases<br /><span>will appear here.</span></div>`;
  return state.cases.map((record) => `
    <button class="case-item ${record.id === state.selectedCaseId ? "active" : ""}" data-case-id="${esc(record.id)}">
      <span class="case-avatar">${esc((record.query || "?").slice(0, 1).toUpperCase())}</span>
      <span class="case-item-copy"><b>${esc(record.query)}</b><small>${esc((record.result.entity?.type || "subject").toUpperCase())} · ${esc(shortDate(record.updatedAt))}</small></span>
      <span class="case-arrow">›</span>
    </button>`).join("");
}

function tabButton(tab, title, icon, disabled = false) {
  return `<button class="result-tab ${state.tab === tab ? "active" : ""}" data-tab="${tab}" ${disabled ? "disabled" : ""}><span>${icon}</span>${title}</button>`;
}

function render() {
  const record = currentCase();
  const domain = record?.result?.entity?.type === "domain";
  const username = record?.result?.entity?.type === "username";
  const inTools = state.view === "tools";
  ROOT.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand-lockup"><div class="brand-mark">u<span>w</span></div><div><b>uwu<span>osint</span></b><small>PUBLIC SURFACE WORKSPACE</small></div></div>
        <div class="sidebar-rule"></div>
        <div class="side-label">WORKSPACE</div>
        <button class="side-link ${inTools ? "" : "selected"}" data-action="open-workspace"><span class="side-icon">▦</span>Research board${inTools ? "" : `<span class="nav-dot"></span>`}</button>
        <button class="side-link" data-action="new-case"><span class="side-icon">＋</span>New case</button>
        <button class="side-link ${inTools ? "selected" : ""}" data-action="open-tools"><span class="side-icon">⌘</span>Built-in modules${inTools ? `<span class="nav-dot"></span>` : ""}</button>
        <div class="case-section-heading"><span class="side-label">RECENT CASES</span><span class="case-count">${state.cases.length}</span></div>
        <div class="case-list">${caseList()}</div>
        <div class="sidebar-bottom"><div class="local-indicator"><i></i><span>Local workspace</span></div><p>Cases are stored in this browser. No account required.</p><div class="version-label">UWU OSINT <span>0.1.0</span></div></div>
      </aside>
      <main class="main-content">
        <header class="topbar"><div class="breadcrumb"><span>Workspace</span><i>/</i><b>${inTools ? "Built-in modules" : "Research board"}</b></div><div class="topbar-actions"><button class="topbar-view-switch" data-action="${inTools ? "open-workspace" : "open-tools"}">${inTools ? "Research board" : "Built-in modules"}</button><span class="passive-label"><i></i>PUBLIC SOURCE QUERIES</span>${record && !inTools ? `<button class="icon-button" data-action="refresh-case" title="Refresh current case" aria-label="Refresh current case" ${state.busy ? "disabled" : ""}>↻</button><button class="icon-button" data-action="export-csv" title="Export evidence as CSV" aria-label="Export evidence as CSV">▤</button><button class="icon-button" data-action="export" title="Export current case as JSON" aria-label="Export current case as JSON">⇩</button>` : ""}</div></header>
        <div class="content-wrap">
          <section class="page-heading"><div><span class="eyebrow">${inTools ? "NATIVE RESEARCH MODULES" : `INTELLIGENCE / ${record ? esc(record.result.entity?.type?.toUpperCase()) : "START HERE"}`}</span><h1>${inTools ? `Research <em>modules.</em>` : `Public surface <em>research.</em>`}</h1><p>${inTools ? "Built-in collection, local file inspection, and report interchange." : "Bring public infrastructure and self-audit signals into one source-linked workspace."}</p></div><div class="heading-ornament"><div class="ornament-ring ring-one"></div><div class="ornament-ring ring-two"></div><div class="ornament-core">uwu</div></div></section>
          ${inTools ? "" : `<form class="search-panel" id="lookup-form"><div class="search-icon">⌕</div><div class="search-input-wrap"><label for="query">SUBJECT</label><input id="query" name="query" value="${esc(username ? `@${record.result.entity.value}` : record?.query || "")}" placeholder="example.com, public IP, AS15169, or @username" autocomplete="off" ${state.busy ? "disabled" : ""} /><div class="search-hint">Domain · public IP · ASN · self-audit username</div><div class="account-filter" id="account-filter" ${username ? "" : "hidden"}><label for="account-category">PROFILE CATEGORY</label><select id="account-category" name="category" ${state.accountCategories.length ? "" : "disabled"}><option value="all">All categories</option>${state.accountCategories.map((item) => `<option value="${esc(item)}" ${state.accountCategory === item ? "selected" : ""}>${esc(item)}</option>`).join("")}</select></div></div><div class="search-divider"></div><div class="scope-check"><label><input type="checkbox" name="scope" ${state.busy ? "disabled" : ""} /><span class="custom-check"></span><span>I own this account or asset, or have permission to research it</span></label><button class="submit-button" type="submit" ${state.busy ? "disabled" : ""}>${state.busy ? `<span class="spinner"></span>Collecting` : `Investigate <span>↗</span>`}</button></div></form>`}
          ${state.flash && !inTools ? `<div class="flash-message" role="status">${esc(state.flash)}</div>` : ""}
          ${inTools ? toolsDirectory() : record ? `
            <section class="case-title-row"><div><div class="subject-line"><span class="subject-dot"></span><h2>${esc(record.query)}</h2><span class="type-tag">${esc(record.result.entity?.type || "subject")}</span></div><p>Case opened ${esc(shortDate(record.createdAt))} <span class="middle-dot">·</span> Refreshed ${esc(shortDate(record.updatedAt))}</p></div><button class="delete-button" data-action="delete-case">Delete case <span>×</span></button></section>
            <nav class="result-tabs" aria-label="Case views">${tabButton("overview", "Overview", "◫")}${username ? tabButton("accounts", "Account footprint", "◎") : ""}${domain ? tabButton("dns", "DNS records", "⌁") : ""}${domain ? tabButton("certificates", "Certificates", "▤") : ""}${domain ? tabButton("subdomains", "Subdomain map", "⌘") : ""}${!username ? tabButton("registration", "Registration", "◈") : ""}${tabButton("imports", "Imported reports", "⇧")}</nav>
            <div class="result-content">${contentFor(record)}</div>
          ` : `<section class="welcome-grid"><article class="welcome-card"><div class="welcome-icon">⌁</div><span class="eyebrow">01 / COLLECT</span><h2>Start with an asset or account</h2><p>Enter a domain, public IP, ASN, or a username for an account you own. Confirm authorization before starting.</p><div class="welcome-example"><span>TRY A FORMAT</span><code>example.com · @handle</code></div></article><article class="welcome-card"><div class="welcome-icon">◈</div><span class="eyebrow">02 / CONNECT</span><h2>Keep the evidence together</h2><p>Each source reports independently. Findings include collection times, provider links, and a private case notebook.</p><div class="welcome-example"><span>CASE STORAGE</span><code>Only in this browser</code></div></article><article class="welcome-card"><div class="welcome-icon">⇩</div><span class="eyebrow">03 / EXPORT</span><h2>Take your work with you</h2><p>Save a case as JSON for your records or for later processing by another research tool.</p><div class="welcome-example"><span>EXPORT FORMAT</span><code>JSON · source-linked</code></div></article></section>
            <section class="getting-started"><div><span class="eyebrow">BUILT FOR CAREFUL RESEARCH</span><h3>Scoped source requests</h3><p>Infrastructure checks use public records. Account self-audits request public profile URLs without signing in.</p></div><div class="provider-chips"><span>Cloudflare DNS</span><span>IANA RDAP</span><span>crt.sh</span><span>Host Search</span></div></section>`}
          <footer class="page-footer"><span>UWU OSINT · LOCAL-FIRST RESEARCH</span><span>Public data can be incomplete or out of date. Verify important findings at their source.</span></footer>
        </div>
      </main>
    </div>`;
  if (username) populateAccountCategories();
}

async function populateAccountCategories() {
  if (state.accountCategories.length || state.categoriesLoading) return;
  state.categoriesLoading = true;
  try {
    const response = await fetch("/api/account-categories");
    const data = await response.json();
    if (!response.ok || !Array.isArray(data.categories)) return;
    state.accountCategories = data.categories;
    const select = document.querySelector("#account-category");
    if (!select) return;
    select.replaceChildren(new Option("All categories", "all"));
    for (const category of state.accountCategories) select.add(new Option(category, category));
    select.value = state.accountCategory;
    select.disabled = false;
  } catch {
    // The default all-category lookup still works when the category list cannot load.
  } finally {
    state.categoriesLoading = false;
  }
}

async function investigate(query, authorized, category = "all", existingCaseId = null) {
  state.busy = true;
  state.flash = "";
  render();
  try {
    const response = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, authorized, category, limit: 25 }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The lookup could not be completed.");
    const timestamp = data.generatedAt || new Date().toISOString();
    const entityType = data.entity?.type || "subject";
    const entityValue = String(data.entity?.value || query).toLowerCase();
    const record = state.cases.find((item) => item.id === existingCaseId)
      || state.cases.find((item) => item.result.entity?.type === entityType
        && String(item.result.entity?.value || "").toLowerCase() === entityValue);
    const displayQuery = entityType === "username" ? `@${data.entity.value}` : data.entity?.value || query;
    if (record) {
      const savedImports = record.result.modules?.imports || [];
      data.modules ||= {};
      if (savedImports.length) data.modules.imports = savedImports;
      record.query = displayQuery;
      record.updatedAt = timestamp;
      record.result = data;
      state.flash = "Case updated. Your notes and imported reports were preserved.";
    } else {
      const newRecord = {
        id: globalThis.crypto?.randomUUID?.() || `case-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        query: displayQuery,
        createdAt: timestamp,
        updatedAt: timestamp,
        notes: "",
        result: data,
      };
      state.cases.unshift(newRecord);
      state.selectedCaseId = newRecord.id;
    }
    if (record) state.selectedCaseId = record.id;
    state.tab = "overview";
    persistCases();
  } catch (error) {
    state.flash = error instanceof TypeError ? "Could not reach the local lookup server. Restart server.py and try again." : error.message;
  } finally {
    state.busy = false;
    render();
  }
}

function exportCase(record) {
  const content = JSON.stringify(record, null, 2);
  const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `uwu-osint-${(record.query || "case").replace(/[^a-z0-9.-]+/gi, "-")}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[\t\r\n ]*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function exportEvidenceCsv(record) {
  const modules = record.result.modules || {};
  const rows = [["subject", "entity_type", "finding_type", "value", "source", "collected_at", "details"]];
  const add = (type, value, source, collectedAt, details = "") => {
    if (value == null || value === "") return;
    rows.push([record.query, record.result.entity?.type || "subject", type, value, source, collectedAt || "", details]);
  };

  for (const [recordType, answers] of Object.entries(modules.dns?.records || {})) {
    for (const answer of answers || []) add(`DNS ${recordType}`, answer.data, "Cloudflare DNS", modules.dns.queriedAt, answer.ttl == null ? "" : `TTL ${answer.ttl}s`);
  }
  const registry = modules.registration || {};
  add("Registry network type", registry.networkType, "IANA RDAP", registry.queriedAt);
  add("Registry country", registry.country, "IANA RDAP", registry.queriedAt);
  if (registry.startAddress || registry.endAddress) add("Registry address range", [registry.startAddress, registry.endAddress].filter(Boolean).join(" – "), "IANA RDAP", registry.queriedAt);
  for (const cidr of registry.cidrs || []) add("Registry CIDR", cidr, "IANA RDAP", registry.queriedAt);
  if (registry.startAutnum != null) add("Registry ASN range", `AS${registry.startAutnum} – AS${registry.endAutnum}`, "IANA RDAP", registry.queriedAt);
  for (const nameserver of registry.nameservers || []) add("Registered nameserver", nameserver, "IANA RDAP", registry.queriedAt);
  for (const certificate of modules.certificates?.names || []) {
    add("Certificate name", certificate.name, "crt.sh", modules.certificates.queriedAt, certificate.firstSeen ? `First seen ${certificate.firstSeen}` : "");
  }
  for (const host of modules.subdomains?.hosts || []) {
    const providers = (host.sources || []).join(", ") || "Passive host discovery";
    add("Subdomain", host.name, providers, modules.subdomains.queriedAt);
    for (const address of host.addresses || []) add("Resolved address", address, providers, modules.subdomains.queriedAt, host.name);
  }
  for (const site of modules.accounts?.sites || []) {
    add(`Profile ${site.status}`, site.url || site.site, "Public profile check", modules.accounts.queriedAt, site.category || "");
  }
  for (const report of modules.imports || []) {
    for (const finding of report.findings || []) add(`Imported ${finding.type}`, finding.value, report.tool || "Imported report", report.queriedAt, "In-scope infrastructure finding");
  }

  const content = `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `uwu-osint-${(record.query || "case").replace(/[^a-z0-9.-]+/gi, "-")}-evidence.csv`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"' && quoted && text[index + 1] === '"') {
      field += '"';
      index += 1;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (character === "," && !quoted) {
      row.push(field);
      field = "";
    } else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(field);
      if (row.some((item) => item.trim())) rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  row.push(field);
  if (row.some((item) => item.trim())) rows.push(row);
  const headers = (rows.shift() || []).map((item) => item.trim().toLowerCase());
  return rows.slice(0, 10000).map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] || ""])));
}

function normalizedFinding(value, typeHint, scope) {
  if (typeof value !== "string") return null;
  let candidate = value.trim().replace(/^\*\./, "").replace(/\.$/, "");
  if (!candidate || candidate.length > 253 || candidate.includes("@") || /[\s,;<>]/.test(candidate)) return null;
  if (/^https?:\/\//i.test(candidate)) {
    try { candidate = new URL(candidate).hostname.toLowerCase(); } catch { return null; }
  }
  const ipV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate) && candidate.split(".").every((octet) => Number(octet) <= 255);
  let ipV6 = false;
  if (candidate.includes(":")) {
    try { ipV6 = new URL(`http://[${candidate}]/`).hostname.length > 0; } catch { ipV6 = false; }
  }
  const scopeValue = String(scope.value || "").toLowerCase();
  const scopeDomain = scope.type === "domain" ? scopeValue : null;
  if (ipV4 || ipV6) {
    if (scope.type === "ip") return candidate.toLowerCase() === scopeValue ? { type: "IP", value: candidate } : null;
    if (scope.type !== "domain" || !scope.allowedIps?.has(candidate.toLowerCase())) return null;
    return { type: "IP", value: candidate };
  }
  candidate = candidate.toLowerCase();
  if (!/(?:^|\.)(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(candidate)) return null;
  if (scopeDomain && candidate !== scopeDomain && !candidate.endsWith(`.${scopeDomain}`)) return null;
  if (!scopeDomain) return null;
  if (/email|person|phone|user|account|address|contact|credential|leak/.test(typeHint)) return null;
  return { type: "HOST", value: candidate };
}

function collectInfrastructure(value, scope, output, hint = "") {
  if (output.length >= 2000 || value == null) return;
  if (Array.isArray(value)) {
    for (const item of value) collectInfrastructure(item, scope, output, hint);
    return;
  }
  if (!value || typeof value !== "object") return;
  const typeHint = String(value.type || value.eventType || value.event_type || value.kind || hint).toLowerCase();
  if (/email|person|phone|username|social|contact|credential|breach|password/.test(typeHint)) return;
  const ipKeys = new Set(["ip", "ip_address", "ipaddress", "ipv4", "ipv6", "address_ip"]);
  const hostKeys = new Set(["host", "hostname", "domain", "subdomain", "fqdn", "internet_name", "name_value"]);
  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[ -]/g, "_");
    const candidateHint = `${typeHint} ${normalizedKey}`;
    if (typeof child === "string" && (ipKeys.has(normalizedKey) || hostKeys.has(normalizedKey) || (normalizedKey === "data" && /host|domain|internet_name|ip_address/.test(typeHint)))) {
      const finding = normalizedFinding(child, candidateHint, scope);
      if (finding) output.push(finding);
    }
    if (typeof child === "object") collectInfrastructure(child, scope, output, typeHint);
  }
}

async function importReport() {
  const record = currentCase();
  const file = document.querySelector("#report-file")?.files?.[0];
  if (!record) {
    state.flash = "Open or create a case before importing a report.";
    render();
    return;
  }
  if (!file) {
    state.flash = "Choose a JSON, JSONL, or CSV report to import.";
    render();
    return;
  }
  if (file.size > 4_000_000) {
    state.flash = "The report exceeds the 4 MB import limit.";
    render();
    return;
  }
  try {
    const text = await file.text();
    const allowedIps = new Set();
    for (const row of [...(record.result.modules?.dns?.records?.A || []), ...(record.result.modules?.dns?.records?.AAAA || [])]) {
      allowedIps.add(String(row.data).toLowerCase());
    }
    for (const host of record.result.modules?.subdomains?.hosts || []) {
      for (const address of host.addresses || []) allowedIps.add(String(address).toLowerCase());
    }
    const scope = { ...(record.result.entity || {}), allowedIps };
    const findings = [];
    if (file.name.toLowerCase().endsWith(".csv")) {
      collectInfrastructure(parseCsv(text), scope, findings);
    } else if (file.name.toLowerCase().endsWith(".jsonl")) {
      const parsed = [];
      for (const line of text.split(/\r?\n/).filter((item) => item.trim()).slice(0, 10000)) {
        try { parsed.push(JSON.parse(line)); } catch { /* Ignore non-JSON progress lines. */ }
      }
      collectInfrastructure(parsed, scope, findings);
    } else {
      collectInfrastructure(JSON.parse(text), scope, findings);
    }
    const unique = Array.from(new Map(findings.map((item) => [`${item.type}:${item.value}`, item])).values());
    const tool = document.querySelector("#import-tool")?.value || "Imported tool";
    if (!record.result.modules.imports) record.result.modules.imports = [];
    record.result.modules.imports.push({
      status: "ok",
      tool,
      source: "Local report import",
      queriedAt: new Date().toISOString(),
      findings: unique,
      droppedPersonalFields: true,
    });
    record.updatedAt = new Date().toISOString();
    state.flash = `${unique.length} in-scope infrastructure finding${unique.length === 1 ? "" : "s"} imported from ${tool}.`;
    persistCases();
    render();
  } catch {
    state.flash = "Could not parse that report. Choose a valid JSON, JSONL, or CSV export.";
    render();
  }
}

async function inspectLocalFile() {
  const file = document.querySelector("#metadata-file")?.files?.[0];
  const authorized = document.querySelector("#metadata-scope")?.checked;
  if (!authorized) {
    state.flash = "Confirm that this is your file or that you have permission to inspect it.";
    render();
    return;
  }
  if (!file) {
    state.flash = "Choose a local file to inspect.";
    render();
    return;
  }
  if (file.size > 10_000_000) {
    state.flash = "The file exceeds the 10 MB limit.";
    render();
    return;
  }
  state.metadataBusy = true;
  state.flash = "";
  render();
  try {
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("Could not read the selected file."));
      reader.readAsDataURL(file);
    });
    const content = dataUrl.split(",", 2)[1] || "";
    const response = await fetch("/api/metadata", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, content, authorized: true }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The local parser could not inspect this file.");
    state.metadataResult = result;
  } catch (error) {
    state.flash = error instanceof TypeError ? "Could not reach the local lookup server." : error.message;
  } finally {
    state.metadataBusy = false;
    render();
  }
}

ROOT.addEventListener("submit", (event) => {
  if (event.target.id !== "lookup-form") return;
  event.preventDefault();
  const form = new FormData(event.target);
  const query = String(form.get("query") || "").trim();
  const category = String(form.get("category") || "all");
  if (!query) {
    state.flash = "Enter a domain, public IP address, ASN, or @username to start.";
    render();
    document.querySelector("#query")?.focus();
    return;
  }
  if (!form.get("scope")) {
    state.flash = "Confirm you own the account or asset, or have permission to research it.";
    render();
    document.querySelector("[name=scope]")?.focus();
    return;
  }
  investigate(query, true, category);
});

ROOT.addEventListener("click", (event) => {
  const caseButton = event.target.closest("[data-case-id]");
  if (caseButton) {
    state.selectedCaseId = caseButton.dataset.caseId;
    state.tab = "overview";
    state.flash = "";
    render();
    return;
  }
  const tabButton = event.target.closest("[data-tab]");
  if (tabButton && !tabButton.disabled) {
    state.tab = tabButton.dataset.tab;
    render();
    return;
  }
  const actionButton = event.target.closest("[data-action]");
  if (!actionButton) return;
  const action = actionButton.dataset.action;
  if (action === "open-tools") {
    state.view = "tools";
    state.flash = "";
    render();
  } else if (action === "open-workspace") {
    state.view = "workspace";
    state.flash = "";
    render();
  } else if (action === "new-case") {
    state.view = "workspace";
    state.selectedCaseId = null;
    state.tab = "overview";
    state.flash = "";
    render();
    document.querySelector("#query")?.focus();
  } else if (action === "export") {
    const record = currentCase();
    if (record) exportCase(record);
  } else if (action === "export-csv") {
    const record = currentCase();
    if (record) exportEvidenceCsv(record);
  } else if (action === "refresh-case") {
    const record = currentCase();
    if (!record) return;
    const authorized = document.querySelector("[name=scope]")?.checked;
    if (!authorized) {
      state.flash = "Confirm authorization in the checkbox above before refreshing this case.";
      render();
      document.querySelector("[name=scope]")?.focus();
      return;
    }
    const category = record.result.entity?.type === "username"
      ? record.result.modules?.accounts?.category || "all"
      : "all";
    investigate(record.query, true, category, record.id);
  } else if (action === "delete-case") {
    const record = currentCase();
    if (!record || !window.confirm(`Delete the local case for ${record.query}?`)) return;
    state.cases = state.cases.filter((item) => item.id !== record.id);
    state.selectedCaseId = state.cases[0]?.id ?? null;
    state.tab = "overview";
    persistCases();
    render();
  } else if (action === "import-report") {
    importReport();
  } else if (action === "audit-metadata") {
    inspectLocalFile();
  }
});

ROOT.addEventListener("input", (event) => {
  if (event.target.matches("#query")) {
    const isUsername = /^(?:@|username:)/i.test(event.target.value.trim());
    const filter = document.querySelector("#account-filter");
    if (filter) filter.hidden = !isUsername;
    if (isUsername) populateAccountCategories();
    return;
  }
  if (!event.target.matches("[data-notes]")) return;
  const record = currentCase();
  if (!record) return;
  record.notes = event.target.value;
  record.updatedAt = new Date().toISOString();
  persistCases();
});

ROOT.addEventListener("change", (event) => {
  if (event.target.matches("#account-category")) state.accountCategory = event.target.value;
});

render();
