const STORAGE_KEY = "uwu-osint-cases-v1";
const ROOT = document.querySelector("#app");
const DEFAULT_DOMAIN_SOURCES = ["crtsh", "hackertarget"];

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
  accountPreview: [],
  accountPreviewStale: false,
  accountPreviewRevision: "",
  accountPreviewCategory: null,
  accountPreviewRequest: 0,
  categoriesLoading: false,
  accountCategory: "all",
  metadataBusy: false,
  metadataResult: null,
  externalQuery: "",
  externalAuthorized: false,
  externalOtxUrlAcknowledged: false,
  graphSelection: "",
  graphQuery: "",
  graphTypeFilter: "all",
  graphSourceFilter: "all",
  graphZoom: 100,
  revealSensitive: false,
  pivotQuery: "",
  monitorTimer: null,
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
  armMonitorScheduler();
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
  const status = module?.status === "ok" ? "available" : module?.status === "partial" ? "partial" : module?.status === "skipped" ? "skipped" : "unavailable";
  const text = module?.status === "ok" ? label : module?.status === "partial" ? "Partial" : module?.status === "skipped" ? "Skipped" : "Unavailable";
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
  if (modules.emailAudit) sources.push({ title: "Mail-domain policy records", name: "Cloudflare", module: modules.emailAudit, icon: "✉" });
  if (modules.reverseDns) sources.push({ title: "Reverse DNS (PTR)", name: "Cloudflare", module: modules.reverseDns, icon: "↩" });
  if (modules.certificates) sources.push({ title: "Certificate transparency", name: "crt.sh", module: modules.certificates, icon: "▤" });
  if (modules.registration) sources.push({ title: "Registration data", name: "IANA RDAP", module: modules.registration, icon: "◈" });
  if (modules.subdomains) {
    for (const provider of modules.subdomains.providers || []) {
      sources.push({
        title: provider.archive ? `${provider.name} · ${provider.archive}` : provider.name,
        name: provider.name,
        module: { ...modules.subdomains, status: provider.status, source: provider.source },
        icon: provider.name.includes("Certificate") ? "▤" : provider.name.includes("Crawl") ? "◷" : "⌘",
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
  if (result.entity?.type === "email" || result.entity?.type === "email-domain") return emailOverview(record);
  if (result.entity?.type === "phone") return phoneOverview(record);
  if (result.entity?.type === "ip" || result.entity?.type === "asn") return networkOverview(record);
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
        ${modules.dns?.status === "ok" || modules.dns?.status === "partial" ? `<div class="pill-row">${dnsSummary(modules.dns)}</div>` : `<div class="inline-error">${esc(modules.dns?.error || modules.dns?.errors?.join(" · ") || "DNS collection was not run for this subject.")}</div>`}
        ${modules.dns?.errors?.length ? `<div class="subtle-note">${esc(modules.dns.errors.length)} record type(s) could not be retrieved.</div>` : ""}
      </article>
      <article class="panel overview-panel">
        <div class="panel-heading"><div><span class="eyebrow">02 / CERTIFICATE LOGS</span><h3>Observed names</h3></div>${domain ? `<button class="text-button" data-tab="certificates">View details <span>→</span></button>` : ""}</div>
        ${domain ? (modules.certificates?.status === "ok" ? `<div class="summary-number">${certCount}<span> certificate name${certCount === 1 ? "" : "s"}</span></div><div class="subtle-note">Names in public certificate transparency records.</div>` : modules.certificates?.status === "skipped" ? `<div class="subtle-note">Not selected for this collection.</div>` : `<div class="inline-error">${esc(modules.certificates?.error || "Certificate lookup was not available.")}</div>`) : `<div class="subtle-note">Certificate discovery is available for domain cases.</div>`}
      </article>
      ${domain ? `<article class="panel overview-panel">
        <div class="panel-heading"><div><span class="eyebrow">03 / PASSIVE HOST DISCOVERY</span><h3>Subdomain map</h3></div><button class="text-button" data-tab="subdomains">View map <span>→</span></button></div>
        ${modules.subdomains?.status === "ok" || modules.subdomains?.status === "partial" ? `<div class="summary-number">${hostCount}<span> scoped host${hostCount === 1 ? "" : "s"}</span></div><div class="subtle-note">${esc(modules.subdomains.resolvedCount ?? 0)} hosts resolved to public addresses.${modules.subdomains.status === "partial" ? " One or more selected sources failed." : ""}</div>` : `<div class="inline-error">${esc(modules.subdomains?.error || "No passive host data returned.")}</div>`}
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
    ${monitorPanel(record)}
    ${notesPanel(record)}
  `;
}

function emailOverview(record) {
  const modules = record.result.modules || {};
  const audit = modules.emailAudit;
  const dnsCount = countDns(modules.dns);
  const registration = modules.registration;
  const entity = record.result.entity || {};
  const emailDomain = entity.domain || "";
  const hasMailbox = entity.type === "email";
  const policy = (value) => value === "published" ? "Published" : value === "ambiguous" ? "Multiple records" : value === "missing" ? "No record" : "Unknown";
  return `<div class="notice ${hasMailbox ? "warning-notice" : ""}">${hasMailbox ? `Email address is stored in this browser case. Network requests use only <code>${esc(emailDomain)}</code>; the full address is not sent to public DNS or registry sources.` : `Only the domain <code>${esc(emailDomain)}</code> is stored and sent to public DNS and registry sources. No mailbox identifier was entered.`}</div>
    <div class="metrics-grid">
      <article class="metric-card"><span class="metric-label">DNS answers</span><strong>${dnsCount}</strong><span class="metric-foot">For the email domain only</span></article>
      <article class="metric-card"><span class="metric-label">MX records</span><strong class="metric-word">${esc(policy(audit?.mxStatus))}</strong><span class="metric-foot">Mail routing published in DNS</span></article>
      <article class="metric-card"><span class="metric-label">SPF records</span><strong class="metric-word">${esc(policy(audit?.spfStatus))}</strong><span class="metric-foot">Matching sender-policy TXT records</span></article>
      <article class="metric-card"><span class="metric-label">DMARC records</span><strong class="metric-word">${esc(policy(audit?.dmarcStatus))}</strong><span class="metric-foot">Matching _dmarc TXT records</span></article>
    </div>
    <section class="overview-grid">
      <article class="panel overview-panel"><div class="panel-heading"><div><span class="eyebrow">01 / MAIL DOMAIN</span><h3>Public mail configuration</h3></div><button class="text-button" data-tab="email">View audit <span>→</span></button></div>
        <div class="detail-list"><div class="detail-row"><span>MX</span><b>${esc(policy(audit?.mxStatus))}</b></div><div class="detail-row"><span>SPF records</span><b>${esc(policy(audit?.spfStatus))}</b></div><div class="detail-row"><span>DMARC records</span><b>${esc(policy(audit?.dmarcStatus))}</b></div></div>
      </article>
      <article class="panel overview-panel"><div class="panel-heading"><div><span class="eyebrow">02 / DOMAIN REGISTRY</span><h3>Registration</h3></div>${registration?.source ? safeLink(registration.source, "RDAP record") : ""}</div>
        ${registration?.status === "ok" ? registrationPreview(registration, "domain") : `<div class="inline-error">${esc(registration?.error || "Registration lookup is not available.")}</div>`}
      </article>
    </section>
    <div class="notice">${esc(audit?.notice || "This checks public domain DNS only. It does not verify a mailbox or identify its owner.")}</div>
    <section class="panel sources-panel"><div class="panel-heading"><div><span class="eyebrow">COLLECTION PROVENANCE</span><h3>Sources & timestamps</h3></div><span class="panel-caption">Domain-level records only</span></div>${sourceCards(record.result)}</section>
    ${monitorPanel(record)}${notesPanel(record)}`;
}

function phoneOverview(record) {
  const validation = record.result.modules?.phoneValidation;
  const displayedNumber = state.revealSensitive ? validation?.normalized || record.result.entity?.value : caseSubjectLabel(record);
  return `<div class="notice warning-notice">Phone number is stored in this browser case. This check runs locally and makes no network lookup.</div>
    <div class="metrics-grid">
      <article class="metric-card"><span class="metric-label">Format</span><strong class="metric-word">${esc(validation?.format || "E.164")}</strong><span class="metric-foot">International number format</span></article>
      <article class="metric-card"><span class="metric-label">Shape check</span><strong class="metric-word">${validation?.validShape ? "Valid" : "Unavailable"}</strong><span class="metric-foot">Syntax only, not number assignment</span></article>
      <article class="metric-card"><span class="metric-label">Digits</span><strong>${esc(validation?.digitCount ?? "—")}</strong><span class="metric-foot">Country code included</span></article>
      <article class="metric-card"><span class="metric-label">Network requests</span><strong class="metric-word">None</strong><span class="metric-foot">No lookup was performed</span></article>
    </div>
    <section class="panel overview-panel account-summary"><div class="panel-heading"><div><span class="eyebrow">LOCAL FORMAT CHECK</span><h3>${esc(displayedNumber || "Phone number")}</h3></div><button class="text-button" data-tab="phone">View details <span>→</span></button></div>
      <p class="account-disclaimer">${esc(validation?.notice || "Syntax only. No subscriber, carrier, location, or account information is queried.")}</p>
    </section>${notesPanel(record)}`;
}

function networkOverview(record) {
  const entity = record.result.entity || {};
  const registration = record.result.modules?.registration;
  const reverse = record.result.modules?.reverseDns;
  const isIp = entity.type === "ip";
  const addressRange = [registration?.startAddress, registration?.endAddress].filter(Boolean).join(" – ") || "No range returned";
  const asnRange = registration?.startAutnum != null ? `AS${registration.startAutnum} – AS${registration.endAutnum}` : entity.value;
  const registrationLabel = registration?.status === "ok" ? "Found" : registration?.status === "error" ? "Unavailable" : "Pending";
  return `<div class="notice">RDAP describes the registry allocation for this public network value. It does not identify a device or prove who uses the address.</div>
    <div class="metrics-grid">
      <article class="metric-card"><span class="metric-label">${isIp ? "Reverse DNS names" : "Autonomous system"}</span><strong class="metric-word">${esc(isIp ? reverse?.names?.length ?? 0 : entity.value || "—")}</strong><span class="metric-foot">${isIp ? "Public PTR records" : "Network identifier"}</span></article>
      <article class="metric-card"><span class="metric-label">${isIp ? "Address range" : "ASN range"}</span><strong class="metric-word">${esc(isIp ? addressRange : asnRange)}</strong><span class="metric-foot">From the registry response</span></article>
      <article class="metric-card"><span class="metric-label">Registry country</span><strong class="metric-word">${esc(registration?.country || "—")}</strong><span class="metric-foot">Allocation record, not geolocation</span></article>
      <article class="metric-card"><span class="metric-label">Registration</span><strong class="metric-word">${esc(registrationLabel)}</strong><span class="metric-foot">${esc(registration?.name || registration?.networkType || registration?.handle || "No registration name returned")}</span></article>
    </div>
    <section class="overview-grid">
      ${isIp ? `<article class="panel overview-panel"><div class="panel-heading"><div><span class="eyebrow">01 / REVERSE DNS</span><h3>PTR names</h3></div><button class="text-button" data-tab="ptr">View details <span>→</span></button></div>${reverse?.status === "ok" ? (reverse.names?.length ? `<div class="pill-row">${reverse.names.slice(0, 8).map((name) => `<span class="mini-pill">${esc(name)}</span>`).join("")}</div>` : `<div class="subtle-note">No PTR answer returned.</div>`) : `<div class="inline-error">${esc(reverse?.error || "Reverse DNS lookup was not available.")}</div>`}<div class="subtle-note">PTR records are set by the address-range operator and may be stale.</div></article>` : `<article class="panel overview-panel"><div class="panel-heading"><div><span class="eyebrow">01 / ASN REGISTRATION</span><h3>Allocation details</h3></div><button class="text-button" data-tab="registration">View record <span>→</span></button></div>${registration?.status === "ok" ? registrationPreview(registration, "asn") : `<div class="inline-error">${esc(registration?.error || "Registration lookup is not available.")}</div>`}</article>`}
      ${isIp ? `<article class="panel overview-panel registration-panel"><div class="panel-heading"><div><span class="eyebrow">02 / REGISTRY RECORD</span><h3>Registration</h3></div>${registration?.source ? safeLink(registration.source, "RDAP record") : ""}</div>${registration?.status === "ok" ? registrationPreview(registration, entity.type) : `<div class="inline-error">${esc(registration?.error || "Registration lookup is not available.")}</div>`}</article>` : ""}
    </section>
    <section class="panel sources-panel"><div class="panel-heading"><div><span class="eyebrow">COLLECTION PROVENANCE</span><h3>Sources & timestamps</h3></div><span class="panel-caption">Public registry and DNS data</span></div>${sourceCards(record.result)}</section>
    ${monitorPanel(record)}${notesPanel(record)}`;
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
  return `<section class="panel notes-panel"><div class="panel-heading"><div><span class="eyebrow">CASE NOTEBOOK</span><h3>Working notes</h3></div><span class="saved-label" data-notes-saved>Saved in this browser</span></div><textarea data-notes aria-label="Case notes" placeholder="Add context, hypotheses, or follow-up questions. These notes stay in local browser storage." rows="3">${esc(record.notes || "")}</textarea></section>`;
}

function monitorPanel(record) {
  const supported = ["domain", "email-domain", "ip", "asn"].includes(record.result?.entity?.type);
  if (!supported) return "";
  const monitor = record.monitor || {};
  const enabled = monitor.enabled === true;
  const intervalHours = [1, 6, 24].includes(Number(monitor.intervalHours)) ? Number(monitor.intervalHours) : 6;
  const status = monitor.lastError
    ? `Last scheduled run failed: ${monitor.lastError}`
    : monitor.lastRunAt ? `Last scheduled run completed ${shortDate(monitor.lastRunAt)} · next ${shortDate(monitor.nextRunAt)}`
      : enabled ? `Next run ${shortDate(monitor.nextRunAt)}` : "Scheduled refresh is off";
  return `<section class="panel monitor-panel"><div class="panel-heading"><div><span class="eyebrow">LOCAL MONITOR</span><h3>Watch this infrastructure case</h3></div><span class="panel-caption">${enabled ? "Enabled while this tab is open" : "Off by default"}</span></div><div class="monitor-controls"><label class="scope-check-inline"><input type="checkbox" data-monitor-toggle ${enabled ? "checked" : ""} /><span class="custom-check"></span><span>Refresh this case while the app is open and visible</span></label><label class="monitor-interval"><span>INTERVAL</span><select data-monitor-interval ${enabled ? "" : "disabled"}><option value="1" ${intervalHours === 1 ? "selected" : ""}>Every hour</option><option value="6" ${intervalHours === 6 ? "selected" : ""}>Every 6 hours</option><option value="24" ${intervalHours === 24 ? "selected" : ""}>Every 24 hours</option></select></label></div><p class="monitor-status">${esc(status)}. The case’s saved providers receive the same authorized infrastructure query; checks pause when this tab is hidden or closed. Disable here to stop them.</p><p class="import-footnote">Enable only for an asset you own or have permission to monitor. No scans are run; the app repeats its selected passive and registry lookups.</p></section>`;
}

function armMonitorScheduler() {
  if (state.monitorTimer) clearTimeout(state.monitorTimer);
  state.monitorTimer = null;
  const monitored = state.cases
    .filter((record) => record.monitor?.enabled === true && ["domain", "email-domain", "ip", "asn"].includes(record.result?.entity?.type))
    .sort((a, b) => Date.parse(a.monitor.nextRunAt || "") - Date.parse(b.monitor.nextRunAt || ""));
  if (!monitored.length) return;
  const nextAt = Date.parse(monitored[0].monitor.nextRunAt || "");
  const delay = Number.isFinite(nextAt) ? Math.max(1000, Math.min(2_147_000_000, nextAt - Date.now())) : 1000;
  state.monitorTimer = setTimeout(runDueMonitor, delay);
}

async function runDueMonitor() {
  state.monitorTimer = null;
  if (document.visibilityState === "hidden" || state.busy) {
    state.monitorTimer = setTimeout(armMonitorScheduler, 60_000);
    return;
  }
  const now = Date.now();
  const record = state.cases.find((item) => item.monitor?.enabled === true
    && ["domain", "email-domain", "ip", "asn"].includes(item.result?.entity?.type)
    && (!Number.isFinite(Date.parse(item.monitor.nextRunAt || "")) || Date.parse(item.monitor.nextRunAt) <= now));
  if (!record) { armMonitorScheduler(); return; }
  const intervalHours = [1, 6, 24].includes(Number(record.monitor.intervalHours)) ? Number(record.monitor.intervalHours) : 6;
  record.monitor.nextRunAt = new Date(now + intervalHours * 60 * 60 * 1000).toISOString();
  record.monitor.lastError = "";
  persistCases();
  const selectedSources = record.result.entity?.type === "domain"
    ? record.collectionOptions?.domainSources || DEFAULT_DOMAIN_SOURCES
    : [];
  await investigate(record.query, true, "all", record.id, selectedSources, true);
  armMonitorScheduler();
}

function disclosureText(value, fallbackEntity = {}, domainSources = DEFAULT_DOMAIN_SOURCES) {
  const raw = String(value || "").trim();
  const query = raw.toLowerCase();
  const type = fallbackEntity.type;
  const entity = fallbackEntity;
  if (!raw) return "Enter a subject to see which public sources may receive it. Submitted cases, results, and notes are stored in this browser until deleted.";
  if (query.startsWith("email-domain:")) {
    const domain = raw.slice(raw.indexOf(":") + 1).trim() || "the domain";
    return `Only ${domain} is stored and sent to Cloudflare DNS and an IANA-selected RDAP registry for MX, SPF, DMARC, and registration data. No mailbox identifier is used. The case, results, and notes stay in this browser until deleted.`;
  }
  if (query.startsWith("email:") || (!query.startsWith("username:") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw))) {
    const address = query.startsWith("email:") ? raw.slice(6).trim() : raw;
    const domain = address.includes("@") ? address.slice(address.lastIndexOf("@") + 1) : entity.domain || "the domain";
    return `The full address is stored in this browser case. Only its domain (${domain}) is sent to Cloudflare DNS and an IANA-selected RDAP registry; no mailbox lookup is made.`;
  }
  if (query.startsWith("username:") || raw.startsWith("@") || type === "username") {
    const handle = query.startsWith("username:") ? raw.slice(9).trim() : raw.replace(/^@/, "");
    return `The handle ${handle || "you enter"} is sent to up to 25 public profile sites selected from a pinned catalog snapshot. The catalog is fetched separately; each selected site may log the request. Results are possible matches, not identity proof. The case is stored in this browser.`;
  }
  if (query.startsWith("phone:") || raw.startsWith("+")) return "Phone format is checked locally; no phone number is sent to a lookup provider. The full number, case, and notes are stored in this browser until deleted.";
  if (/^as\d{1,10}$/i.test(raw) || type === "asn") return `The ASN (${raw}) is sent to the applicable public RDAP registry. The case and results are stored in this browser.`;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw) || (raw.includes(":") && !/^https?:\/\//i.test(raw))) return `The public IP value (${raw}) is sent to an IANA-selected RDAP registry. Its reverse-DNS name is sent to Cloudflare DNS. The case and results are stored in this browser.`;
  if (/^(?:https?:\/\/)?[^\s/]+\.[a-z]{2,}(?:\/.*)?$/i.test(raw) || type === "domain") {
    const passiveSources = [];
    if (domainSources.includes("crtsh")) passiveSources.push("crt.sh certificate search");
    if (domainSources.includes("hackertarget")) passiveSources.push("HackerTarget passive host search");
    if (domainSources.includes("commoncrawl")) passiveSources.push("Common Crawl historical URL index");
    if (domainSources.includes("urlscan")) passiveSources.push("urlscan.io historical public scan search");
    const selected = passiveSources.length ? `the selected passive sources (${passiveSources.join(" and ")})` : "no passive hostname source";
    return `The hostname is sent to Cloudflare DNS, IANA RDAP/bootstrap, and ${selected}. URL paths are ignored by the built-in lookup. Discovered hostnames are resolved with Cloudflare DNS. The case and results are stored in this browser.`;
  }
  return "The app validates the subject before sending requests. Public-source queries are limited to the value and providers needed for the selected lookup; submitted cases, results, and notes are stored in this browser until deleted.";
}

function likelyDomainLookup(value) {
  const raw = String(value || "").trim();
  if (!raw || /^(?:@|username:|email:|email-domain:|phone:|as\d+)/i.test(raw) || /^[^\s@]+@[^\s@]+$/.test(raw)) return false;
  let host = raw;
  if (/^https?:\/\//i.test(raw)) {
    try { host = new URL(raw).hostname; } catch { return false; }
  } else {
    host = raw.split("/", 1)[0].replace(/:\d+$/, "");
  }
  if (!host.includes(".") || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
  const finalLabel = host.replace(/\.$/, "").split(".").at(-1) || "";
  return /^[a-z]{2,}$/i.test(finalLabel);
}

function privacyDisclosure(record, query = "") {
  const savedSources = record?.collectionOptions?.domainSources;
  const domainSources = Array.isArray(savedSources) ? savedSources : DEFAULT_DOMAIN_SOURCES;
  const text = disclosureText(query || record?.query || "", record?.result?.entity || {}, domainSources);
  const isUsername = /^(?:@|username:)/i.test(String(query || record?.query || "").trim());
  return `<section class="privacy-disclosure" aria-label="Lookup data flow"><p class="privacy-preview" id="privacy-preview">${esc(text)}</p><div class="profile-preview" id="profile-preview" ${isUsername ? "" : "hidden"}><b>Profile sites planned for this lookup</b><ul><li>Loading the public profile list…</li></ul><small data-catalog-revision></small><small data-catalog-stale hidden>The catalog request failed; cached pinned rules are being used.</small></div><details><summary>What gets queried and stored?</summary><p>External shortcuts send a query only after you choose a provider and confirm authorization. Provider services may log requests under their own policies. Cases and notes remain in local browser storage until deleted or site data is cleared.</p></details></section>`;
}

function dnsContent(record) {
  const module = record.result.modules?.dns;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">⌁</span><h3>No DNS collection</h3><p>DNS lookups are available when the subject is a domain.</p></div>`;
  if (module.status === "error") return `<div class="empty-panel"><span class="empty-glyph">⌁</span><h3>DNS data unavailable</h3><p>${esc(module.error || module.errors?.join(" · ") || "The DNS source did not return records.")}</p>${safeLink(module.source || "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "Source documentation")}</div>`;
  const groups = Object.entries(module.records ?? {});
  const failedTypes = new Set((module.errors || []).map((error) => String(error).split(":", 1)[0]));
  const dnssec = module.dnssec || {};
  return `<div class="tab-intro"><div><span class="eyebrow">LIVE PUBLIC DNS ANSWERS</span><h2>DNS records</h2><p>Query time ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Provider details")}</div>
    ${module.status === "partial" ? `<div class="notice warning-notice">Some record types could not be retrieved. Failed queries are shown separately from successful empty answers.</div>` : ""}
    ${module.errors?.length ? `<div class="notice warning-notice">${esc(module.errors.join(" · "))}</div>` : ""}
    <div class="notice">DNSSEC AD flag: ${esc(dnssec.authenticatedQueries ?? 0)} of ${esc(dnssec.checkedQueries ?? 0)} DNS replies reported the authenticated-data flag. This is a response flag, not a separate security verdict.</div>
    <div class="record-grid">${groups.map(([type, rows]) => `<section class="panel record-panel"><div class="record-heading"><div><span class="record-type">${esc(type)}</span><h3>${esc(recordTypeName(type))}</h3></div><span class="count-tag">${rows.length}</span></div>
      ${rows.length ? `<ul class="record-list">${rows.map((item) => `<li><code>${esc(item.data)}</code>${item.ttl != null ? `<span>TTL ${esc(item.ttl)}s</span>` : ""}</li>`).join("")}</ul>` : `<div class="empty-record">${failedTypes.has(type) ? "Query failed; result is unknown" : "No answer returned"}</div>`}
    </section>`).join("")}</div>
    ${sourceCards({ modules: { dns: module } })}`;
}

function recordTypeName(type) {
  return ({ A: "IPv4 addresses", AAAA: "IPv6 addresses", CNAME: "Aliases", MX: "Mail exchangers", NS: "Name servers", TXT: "Text records", CAA: "Certificate authorities", SOA: "Zone authority", DS: "DNSSEC delegation signer", DNSKEY: "DNSSEC public keys", HTTPS: "HTTPS service hints" })[type] || type;
}

function certificatesContent(record) {
  const module = record.result.modules?.certificates;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">▤</span><h3>No certificate collection</h3><p>Certificate transparency lookup is available for domain cases.</p></div>`;
  if (module.status === "skipped") return `<div class="empty-panel"><span class="empty-glyph">▤</span><h3>Source not selected</h3><p>Certificate transparency was not queried for this collection. Select it in the collection options above and refresh the case to include it.</p></div>`;
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

function relationshipGraphData(record) {
  const entity = record.result.entity || {};
  const kind = String(entity.type || "").toLowerCase();
  const rootValue = String(entity.value || "").trim();
  const rootDomain = rootValue.toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/, 1)[0].replace(/^\*\./, "").replace(/\.$/, "");
  const nodes = [];
  const edges = [];
  const byKey = new Map();
  const seenEdges = new Set();
  let omitted = 0;
  const maxNodes = 90;
  const addNode = (type, value, options = {}) => {
    const label = String(value ?? "").trim();
    if (!label) return null;
    const key = `${type}:${label.toLowerCase()}`;
    const old = byKey.get(key);
    if (old) {
      old.level = Math.min(old.level, options.level ?? 1);
      if (options.detail && !old.detail) old.detail = options.detail;
      if (options.kind === "record") old.kind = "record";
      return old;
    }
    if (nodes.length >= maxNodes) { omitted += 1; return null; }
    const node = { id: `node-${nodes.length}`, type, kind: options.kind || (type === "host" ? "host" : type === "ip" ? "ip" : "record"), label, detail: String(options.detail || ""), level: options.level ?? 1 };
    nodes.push(node);
    byKey.set(key, node);
    return node;
  };
  const addEdge = (from, to, label, source, queriedAt, detail = "", observedAt = "") => {
    if (!from || !to || from.id === to.id) return;
    const sourceName = String(source || "Source not recorded");
    const key = `${from.id}|${to.id}|${label}|${sourceName}`;
    if (seenEdges.has(key)) return;
    seenEdges.add(key);
    edges.push({ id: `edge-${edges.length}`, from, to, label, source: sourceName, queriedAt: queriedAt || "", observedAt: observedAt || "", detail });
  };
  const inDomainScope = (value) => {
    const hostname = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    return hostname === rootDomain || hostname.endsWith(`.${rootDomain}`);
  };
  if (!rootValue || !["domain", "email-domain", "ip", "asn"].includes(kind)) return { nodes, edges, omitted };
  const root = addNode("root", rootValue, { kind: "root", level: 0, detail: `${kind.toUpperCase()} case subject` });
  const modules = record.result.modules || {};
  if (kind === "domain" || kind === "email-domain") {
    for (const host of (modules.subdomains?.hosts || []).slice(0, 50)) {
      if (!inDomainScope(host.name)) continue;
      const node = addNode("host", host.name, { kind: "host", level: 1, detail: host.resolutionAttempted ? `Hostname · DNS ${host.resolutionStatus || "checked"}` : "Hostname · not resolved in this collection" });
      for (const source of (host.sources || ["Passive hostname source"]).slice(0, 4)) {
        const archivedAt = host.archiveDates?.[source] || "";
        const observedAt = host.observedDates?.[source] || archivedAt;
        const sourceLabel = source === "Common Crawl" ? "hostname in archived crawl" : source === "urlscan.io" ? "hostname in historical public scan" : "hostname observed";
        const sourceDetail = archivedAt ? `Last archived ${shortDate(archivedAt)}` : source === "urlscan.io" && observedAt ? `Last seen in public scan ${shortDate(observedAt)}` : "";
        addEdge(root, node, sourceLabel, source, modules.subdomains?.queriedAt, sourceDetail, observedAt);
      }
      for (const address of (host.addresses || []).slice(0, 3)) {
        const ip = addNode("ip", address, { kind: "ip", level: 2, detail: "Public address returned by DNS resolution" });
        addEdge(node, ip, "resolves to", "Cloudflare DNS", modules.subdomains?.queriedAt);
      }
    }
    for (const cert of (modules.certificates?.names || []).slice(0, 40)) {
      if (!inDomainScope(cert.name)) continue;
      const node = addNode("host", cert.name, { kind: "host", level: 1, detail: `Certificate name${cert.firstSeen ? ` · first seen ${shortDate(cert.firstSeen)}` : ""}` });
      addEdge(root, node, "name listed in certificate transparency", "crt.sh", modules.certificates?.queriedAt, cert.firstSeen ? `First seen ${shortDate(cert.firstSeen)}` : "", cert.firstSeen || "");
    }
    const labels = { A: "A record", AAAA: "AAAA record", CNAME: "CNAME alias", MX: "MX mail host", NS: "NS nameserver" };
    for (const [recordType, rows] of Object.entries(modules.dns?.records || {})) {
      if (!labels[recordType]) continue;
      for (const row of (Array.isArray(rows) ? rows : []).slice(0, 15)) {
        const rawValue = String(row.data || "").trim();
        const value = (recordType === "MX" ? rawValue.split(/\s+/).pop() : rawValue).replace(/\.$/, "");
        if (!value) continue;
        const isAddress = recordType === "A" || recordType === "AAAA";
        const isHost = recordType === "CNAME" || recordType === "MX" || recordType === "NS";
        if (isHost && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)) continue;
        const node = addNode(isAddress ? "ip" : "host", value, { kind: isAddress ? "ip" : recordType === "CNAME" ? "host" : "record", level: isAddress ? 2 : 1, detail: `${recordType} answer from DNS` });
        addEdge(root, node, labels[recordType], "Cloudflare DNS", modules.dns?.queriedAt, row.ttl != null ? `TTL ${row.ttl}s` : "");
      }
    }
    for (const nameserver of (modules.registration?.nameservers || []).slice(0, 12)) {
      const node = addNode("host", nameserver, { kind: "record", level: 1, detail: "Nameserver in the RDAP registration response" });
      addEdge(root, node, "registered nameserver", "IANA RDAP", modules.registration?.queriedAt);
    }
  }
  if (kind === "ip") {
    for (const hostname of (modules.reverseDns?.names || []).slice(0, 20)) {
      const node = addNode("host", hostname, { kind: "host", level: 1, detail: "PTR hostname in the reverse-DNS response" });
      addEdge(root, node, "PTR record names", "Cloudflare DNS", modules.reverseDns?.queriedAt);
    }
  }
  if (kind === "domain" || kind === "email-domain") {
    const resolvedAddresses = new Set([
      ...(modules.subdomains?.hosts || []).flatMap((host) => host.addresses || []),
      ...Object.entries(modules.dns?.records || {}).filter(([type]) => type === "A" || type === "AAAA").flatMap(([, rows]) => (Array.isArray(rows) ? rows : []).map((row) => row.data)),
    ].map((address) => String(address).toLowerCase()));
    for (const report of modules.imports || []) {
      if (!report || typeof report !== "object") continue;
      const reportSource = `Imported report: ${report.tool || "Infrastructure report"}`;
      for (const finding of report.findings || []) {
        if (!finding || typeof finding !== "object") continue;
        const value = String(finding.value || "").trim();
        const reportedSources = Array.isArray(finding.sources) ? finding.sources.filter((source) => typeof source === "string").slice(0, 8) : [];
        const evidenceSources = reportedSources.length ? reportedSources.map((source) => `${reportSource} · ${source}`) : [reportSource];
        if (finding.type === "HOST" && inDomainScope(value)) {
          const node = addNode("host", value, { kind: "host", level: 1, detail: "Hostname finding retained by the case-scope import filter" });
          for (const evidenceSource of evidenceSources) addEdge(root, node, "in-scope report finding", evidenceSource, report.queriedAt, "Hostname retained by the infrastructure-only import filter");
        } else if (finding.type === "IP" && resolvedAddresses.has(value.toLowerCase())) {
          const node = addNode("ip", value, { kind: "ip", level: 2, detail: "IP finding matched an address already resolved in this domain case" });
          for (const evidenceSource of evidenceSources) addEdge(root, node, "in-scope report finding", evidenceSource, report.queriedAt, "Address matched the case’s existing resolved-address scope");
        }
      }
    }
  }
  if (modules.registration && (kind === "ip" || kind === "asn")) {
    const ranges = [...new Set((modules.registration.cidrs || []).filter(Boolean))].slice(0, 20);
    if (!ranges.length && modules.registration.startAddress && modules.registration.endAddress) ranges.push(`${modules.registration.startAddress} – ${modules.registration.endAddress}`);
    for (const range of ranges) {
      const node = addNode("network", range, { kind: "record", level: 1, detail: "Address range in the RDAP response" });
      addEdge(root, node, "included in RDAP allocation", "IANA RDAP", modules.registration.queriedAt, modules.registration.name || modules.registration.networkType || "");
    }
  }
  return { nodes, edges, omitted };
}

function workspaceGraphData() {
  const eligible = state.cases.filter((record) => ["domain", "email-domain", "ip", "asn"].includes(record.result?.entity?.type)).slice(0, 30);
  const nodes = [];
  const edges = [];
  const sharedNodes = new Map();
  const maxNodes = 220;
  const maxEdges = 600;
  let omitted = 0;
  const addSharedNode = (local) => {
    const key = `${local.type}:${String(local.label).toLowerCase()}`;
    let node = sharedNodes.get(key);
    if (node) {
      node.level = Math.min(node.level, local.level ?? 1);
      node.caseIds.add(local.caseId);
      return node;
    }
    if (nodes.length >= maxNodes) { omitted += 1; return null; }
    node = { id: `entity-${nodes.length}`, type: local.type, kind: local.kind, label: local.label, detail: local.detail, level: local.level ?? 1, caseIds: new Set([local.caseId]) };
    nodes.push(node);
    sharedNodes.set(key, node);
    return node;
  };
  for (const [caseIndex, record] of eligible.entries()) {
    const local = relationshipGraphData(record);
    if (!local.edges.length) continue;
    if (nodes.length >= maxNodes) { omitted += local.nodes.length; continue; }
    const caseNode = { id: `case-${caseIndex}`, type: "case", kind: "root", label: caseSubjectLabel(record), detail: `${record.result.entity.type} case · updated ${shortDate(record.updatedAt)}`, level: 0, caseId: record.id, caseIds: new Set([record.id]) };
    nodes.push(caseNode);
    const mapped = new Map();
    for (const localNode of local.nodes) {
      if (localNode.kind === "root") mapped.set(localNode.id, caseNode);
      else mapped.set(localNode.id, addSharedNode({ ...localNode, caseId: record.id }));
    }
    const seen = new Set();
    for (const edge of local.edges) {
      if (edges.length >= maxEdges) { omitted += local.edges.length - seen.size; break; }
      const from = mapped.get(edge.from.id), to = mapped.get(edge.to.id);
      if (!from || !to || from.id === to.id) continue;
      const edgeKey = `${record.id}|${from.id}|${to.id}|${edge.label}|${edge.source}`;
      if (seen.has(edgeKey)) continue;
      seen.add(edgeKey);
      edges.push({ id: `workspace-edge-${edges.length}`, from, to, label: edge.label, source: edge.source, queriedAt: edge.queriedAt || "", observedAt: edge.observedAt || "", detail: edge.detail || "", caseId: record.id, caseLabel: caseSubjectLabel(record) });
    }
  }
  return { nodes, edges, cases: eligible.length, omitted };
}

function workspaceGraphContent() {
  const graph = workspaceGraphData();
  if (!graph.edges.length) return `<div class="tab-intro"><div><span class="eyebrow">CROSS-CASE INFRASTRUCTURE VIEW</span><h2>No infrastructure links to map</h2><p>Save at least one domain, email-domain-only, public IP, or ASN case with collected observations.</p></div></div><div class="empty-panel compact-empty"><h3>This view uses saved cases only</h3><p>It doesn’t make provider requests. Email addresses, phone numbers, and usernames are excluded. Add a scoped infrastructure case to get started.</p></div>`;
  const levels = [...new Set(graph.nodes.map((node) => node.level))].sort((a, b) => a - b);
  const levelNodes = new Map(levels.map((level) => [level, graph.nodes.filter((node) => node.level === level)]));
  const maxCount = Math.max(...[...levelNodes.values()].map((items) => items.length));
  const height = Math.max(380, maxCount * 64 + 80);
  const width = Math.max(1040, 560 + Math.max(...levels) * 330);
  const positions = new Map();
  for (const level of levels) levelNodes.get(level).forEach((node, index) => positions.set(node.id, { x: 24 + level * 330, y: 36 + index * 64 }));
  const edgeHtml = graph.edges.map((edge) => {
    const from = positions.get(edge.from.id), to = positions.get(edge.to.id);
    if (!from || !to) return "";
    const sx = from.x + 232, sy = from.y + 23, tx = to.x, ty = to.y + 23, bend = Math.max(32, (tx - sx) * .4);
    const focus = state.graphSelection ? edge.from.id === state.graphSelection || edge.to.id === state.graphSelection ? "is-connected" : "is-dimmed" : "";
    return `<path class="relationship-edge ${focus}" d="M ${sx} ${sy} C ${sx + bend} ${sy}, ${tx - bend} ${ty}, ${tx} ${ty}" data-edge-from="${edge.from.id}" data-edge-to="${edge.to.id}" data-edge-source="${esc(edge.source)}" aria-hidden="true"><title>${esc(`${edge.caseLabel} · ${edge.label} · ${edge.source} · ${shortDate(edge.queriedAt)}`)}</title></path>`;
  }).join("");
  const nodeHtml = graph.nodes.map((node) => {
    const point = positions.get(node.id), label = node.label.length > 30 ? `${node.label.slice(0, 27)}…` : node.label;
    const secondary = node.kind === "root" ? "root" : node.type;
    return `<g class="relationship-node node-${node.kind} ${state.graphSelection === node.id ? "selected" : ""}" role="button" tabindex="0" aria-label="Select ${esc(node.type)} ${esc(node.label)}" data-graph-node="${node.id}" data-node-kind="${esc(secondary)}" data-node-label="${esc(node.label.toLowerCase())}" transform="translate(${point.x} ${point.y})"><rect width="232" height="46" rx="9"/><circle cx="17" cy="23" r="5"/><text class="relationship-node-type" x="31" y="17">${esc(node.type.toUpperCase())}</text><text class="relationship-node-label" x="31" y="34"><title>${esc(node.label)}</title>${esc(label)}</text></g>`;
  }).join("");
  const selected = graph.nodes.find((node) => node.id === state.graphSelection);
  const selectedEdges = selected ? graph.edges.filter((edge) => edge.from.id === selected.id || edge.to.id === selected.id) : [];
  const selectedCases = selected ? [...selected.caseIds].map((id) => state.cases.find((record) => record.id === id)).filter(Boolean) : [];
  const sources = [...new Set(graph.edges.map((edge) => edge.source))].sort((a, b) => a.localeCompare(b));
  const ledger = graph.edges.map((edge) => `<tr data-ledger-from="${edge.from.id}" data-ledger-to="${edge.to.id}" data-ledger-source="${esc(edge.source)}"><td>${esc(edge.caseLabel)}</td><td><code>${esc(edge.from.label)}</code></td><td>${esc(edge.label)}</td><td><code>${esc(edge.to.label)}</code></td><td>${esc(edge.source)}</td><td>${esc(shortDate(edge.queriedAt))}</td></tr>`).join("");
  const evidence = selectedEdges.map((edge) => `<li data-evidence-source="${esc(edge.source)}"><span class="graph-evidence-direction">${edge.from.id === selected.id ? "OUT" : "IN"}</span><span><b>${esc(edge.label)}</b><small>${esc(edge.caseLabel)} · ${esc(edge.source)} · collected ${esc(shortDate(edge.queriedAt))}${edge.detail ? ` · ${esc(edge.detail)}` : ""}</small></span></li>`).join("");
  const caseLinks = selectedCases.map((record) => `<button class="text-button workspace-case-link" data-case-id="${esc(record.id)}">Open ${esc(caseSubjectLabel(record))}</button>`).join("");
  const canPivot = selected && ["host", "ip"].includes(selected.kind);
  const svgWidth = Math.round(width * state.graphZoom / 100);
  return `<div class="tab-intro"><div><span class="eyebrow">CROSS-CASE INFRASTRUCTURE VIEW</span><h2>Infrastructure relationship graph</h2><p>${graph.nodes.length} entities · ${graph.edges.length} sourced observations · ${graph.cases} eligible cases</p></div><button class="secondary-button" data-action="export-workspace-graph">Export GraphML</button></div><div class="notice graph-notice">This combines saved infrastructure cases and merges identical host/IP observations across them. A shared provider address or nameserver is a technical overlap, not proof of common ownership. Person/contact cases are excluded; no provider requests are made.</div>${graph.omitted ? `<div class="notice">The combined view reached its display limit; ${graph.omitted} entity/edge candidates were omitted. Individual cases retain their full saved results.</div>` : ""}<section class="panel relationship-graph-panel"><div class="relationship-toolbar"><label class="graph-search-field" for="relationship-search"><span>FIND AN ENTITY</span><input id="relationship-search" type="search" value="${esc(state.graphQuery)}" placeholder="Filter cases, hosts, or addresses" autocomplete="off" /></label><label class="graph-filter-field" for="relationship-filter"><span>SHOW</span><select id="relationship-filter"><option value="all" ${state.graphTypeFilter === "all" ? "selected" : ""}>All entities</option><option value="root" ${state.graphTypeFilter === "root" ? "selected" : ""}>Cases</option><option value="host" ${state.graphTypeFilter === "host" ? "selected" : ""}>Hostnames</option><option value="ip" ${state.graphTypeFilter === "ip" ? "selected" : ""}>IP addresses</option><option value="record" ${state.graphTypeFilter === "record" ? "selected" : ""}>DNS / registry</option></select></label><label class="graph-filter-field" for="relationship-source"><span>PROVENANCE</span><select id="relationship-source"><option value="all" ${state.graphSourceFilter === "all" ? "selected" : ""}>All sources</option>${sources.map((source) => `<option value="${esc(source)}" ${state.graphSourceFilter === source ? "selected" : ""}>${esc(source)}</option>`).join("")}</select></label><label class="graph-zoom-field" for="relationship-zoom"><span>ZOOM <output id="graph-zoom-value">${state.graphZoom}%</output></span><input id="relationship-zoom" type="range" min="70" max="160" step="5" value="${state.graphZoom}" aria-label="Graph zoom" /></label><button class="text-button graph-zoom-reset" data-action="reset-graph-zoom">Reset zoom</button><span class="graph-scroll-hint">Select an entity to inspect linked cases</span></div><div class="network-graph-wrap relationship-canvas"><svg class="relationship-svg" style="width:${svgWidth}px;min-width:${svgWidth}px" data-graph-width="${width}" viewBox="0 0 ${width} ${height}" role="group" aria-label="Infrastructure links across saved cases">${edgeHtml}${nodeHtml}</svg></div><div class="relationship-legend"><span><i class="legend-root"></i>Case subject</span><span><i class="legend-host"></i>Hostname</span><span><i class="legend-ip"></i>IP address</span><span><i class="legend-record"></i>DNS / registry record</span></div><p class="graph-filter-empty" id="graph-filter-empty" hidden>No connections match these filters.</p></section>${selected ? `<section class="panel graph-selection-panel" aria-live="polite"><div class="graph-selection-heading"><span><span class="eyebrow">SELECTED ENTITY</span><h3>${esc(selected.label)}</h3><p>${esc(selected.detail || selected.type)} · ${selectedEdges.length} linked observations · ${selectedCases.length} cases</p></span><div class="graph-selection-actions">${canPivot ? `<button class="secondary-button" data-action="pivot-entity" data-pivot-query="${esc(selected.label)}">Use as new case subject</button>` : ""}${caseLinks}<button class="text-button" data-action="clear-graph-selection">Clear selection</button></div></div>${evidence ? `<ul class="graph-evidence-list">${evidence}</ul>` : ""}</section>` : ""}<section class="panel graph-ledger-panel"><div class="panel-heading"><div><span class="eyebrow">SOURCED CASE LINKS</span><h3>Evidence ledger</h3></div><span class="panel-caption">${graph.edges.length} observations</span></div><div class="panel table-panel"><table><thead><tr><th>Case</th><th>From</th><th>Observation</th><th>To</th><th>Source</th><th>Collected</th></tr></thead><tbody>${ledger}</tbody></table></div></section>`;
}

function relationshipTimeline(record, graph) {
  const events = [];
  const collections = new Map();
  const addEvent = (event) => {
    const timestamp = Date.parse(event.date || "");
    if (!Number.isFinite(timestamp)) return;
    events.push({ ...event, timestamp });
  };
  for (const edge of graph.edges) {
    if (edge.queriedAt) {
      const key = `${edge.source}|${edge.queriedAt}`;
      const group = collections.get(key) || { source: edge.source, date: edge.queriedAt, observations: [] };
      group.observations.push(`${edge.label}: ${edge.to.label}`);
      collections.set(key, group);
    }
    if (edge.observedAt) addEvent({
      date: edge.observedAt,
      collectedAt: edge.queriedAt,
      source: edge.source,
      title: edge.source === "Common Crawl" ? "Hostname last archived" : edge.source === "urlscan.io" ? "Hostname last seen in public scan" : "Certificate name first seen",
      detail: edge.to.label,
      kind: "event",
    });
  }
  for (const group of collections.values()) {
    const preview = group.observations.slice(0, 2).join(" · ");
    const remainder = group.observations.length - 2;
    addEvent({
      date: group.date,
      collectedAt: group.date,
      source: group.source,
      title: "Source snapshot collected",
      detail: `${preview}${remainder > 0 ? ` · +${remainder} more` : ""}`,
      count: group.observations.length,
      kind: "collection",
    });
  }
  const registration = record.result.modules?.registration || {};
  for (const event of registration.events || []) addEvent({
    date: event.date,
    collectedAt: registration.queriedAt,
    source: "IANA RDAP",
    title: `Registry event · ${event.action || "event"}`,
    detail: "Event date reported in the registry response",
    kind: "event",
  });
  return events.sort((a, b) => b.timestamp - a.timestamp).slice(0, 100);
}

function relationshipGraphContent(record) {
  const graph = relationshipGraphData(record);
  if (!graph.edges.length) return `<div class="tab-intro"><div><span class="eyebrow">CASE-LOCAL EVIDENCE GRAPH</span><h2>No graphable connections</h2><p>This view is limited to public infrastructure observations. Account, email, and phone subjects are intentionally kept out of infrastructure relationship graphs.</p></div></div><div class="empty-panel compact-empty"><h3>No infrastructure connections in this case</h3><p>Collect domain, DNS, certificate, registration, or reverse-DNS records to build a graph. This view makes no new network requests.</p></div>`;
  const levels = [...new Set(graph.nodes.map((node) => node.level))].sort((a, b) => a - b);
  const levelNodes = new Map(levels.map((level) => [level, graph.nodes.filter((node) => node.level === level)]));
  const height = Math.max(340, Math.max(...[...levelNodes.values()].map((items) => items.length)) * 64 + 80);
  const width = Math.max(760, 560 + Math.max(...levels) * 310);
  const positions = new Map();
  for (const level of levels) levelNodes.get(level).forEach((node, index) => positions.set(node.id, { x: 24 + level * 310, y: level === 0 ? height / 2 - 23 : 40 + index * 64 }));
  const edges = graph.edges.map((edge) => {
    const from = positions.get(edge.from.id), to = positions.get(edge.to.id);
    if (!from || !to) return "";
    const sx = from.x + 232, sy = from.y + 23, tx = to.x, ty = to.y + 23, bend = Math.max(32, (tx - sx) * .45);
    const edgeFocus = state.graphSelection ? edge.from.id === state.graphSelection || edge.to.id === state.graphSelection ? "is-connected" : "is-dimmed" : "";
    return `<path class="relationship-edge ${edgeFocus}" d="M ${sx} ${sy} C ${sx + bend} ${sy}, ${tx - bend} ${ty}, ${tx} ${ty}" data-edge-from="${edge.from.id}" data-edge-to="${edge.to.id}" data-edge-source="${esc(edge.source)}" aria-hidden="true"><title>${esc(`${edge.label} · ${edge.source} · ${shortDate(edge.queriedAt)}`)}</title></path>`;
  }).join("");
  const nodes = graph.nodes.map((node) => {
    const point = positions.get(node.id), label = node.label.length > 30 ? `${node.label.slice(0, 27)}…` : node.label;
    return `<g class="relationship-node node-${node.kind} ${state.graphSelection === node.id ? "selected" : ""}" role="button" tabindex="0" aria-label="Select ${esc(node.type)} ${esc(node.label)}" data-graph-node="${node.id}" data-node-kind="${node.kind}" data-node-label="${esc(node.label.toLowerCase())}" transform="translate(${point.x} ${point.y})"><rect width="232" height="46" rx="9"/><circle cx="17" cy="23" r="5"/><text class="relationship-node-type" x="31" y="17">${esc(node.type.toUpperCase())}</text><text class="relationship-node-label" x="31" y="34"><title>${esc(node.label)}</title>${esc(label)}</text></g>`;
  }).join("");
  const selected = graph.nodes.find((node) => node.id === state.graphSelection);
  const selectedEdges = selected ? graph.edges.filter((edge) => edge.from.id === selected.id || edge.to.id === selected.id) : [];
  const selectedSourceCount = new Set(selectedEdges.map((edge) => edge.source)).size;
  const canPivotSelected = selected && ["host", "ip"].includes(selected.kind);
  const ledger = graph.edges.map((edge) => `<tr data-ledger-from="${edge.from.id}" data-ledger-to="${edge.to.id}" data-ledger-source="${esc(edge.source)}"><td><code>${esc(edge.from.label)}</code></td><td>${esc(edge.label)}</td><td><code>${esc(edge.to.label)}</code></td><td>${esc(edge.source)}</td><td>${esc(shortDate(edge.queriedAt))}${edge.detail ? `<small>${esc(edge.detail)}</small>` : ""}</td></tr>`).join("");
  const timeline = relationshipTimeline(record, graph);
  const sources = [...new Set(graph.edges.map((edge) => edge.source))].sort((a, b) => a.localeCompare(b));
  const selectedEvidence = selectedEdges.map((edge) => `<li data-evidence-source="${esc(edge.source)}"><span class="graph-evidence-direction">${edge.from.id === selected.id ? "OUT" : "IN"}</span><span><b>${esc(edge.label)}</b><small>${esc(edge.from.id === selected.id ? edge.to.label : edge.from.label)} · ${esc(edge.source)} · collected ${esc(shortDate(edge.queriedAt))}</small></span></li>`).join("");
  const timelineRows = timeline.map((event) => `<li class="graph-timeline-row" data-timeline-source="${esc(event.source)}"><time datetime="${esc(event.date)}">${esc(shortDate(event.date))}</time><span class="timeline-kind ${event.kind}">${event.kind === "collection" ? "COLLECTED" : "OBSERVED"}</span><div><b>${esc(event.title)}</b><small>${esc(event.source)} · ${esc(event.detail)}${event.collectedAt && event.kind === "event" ? ` · collected ${esc(shortDate(event.collectedAt))}` : ""}</small></div></li>`).join("");
  const zoomWidth = Math.round(width * state.graphZoom / 100);
  return `<div class="tab-intro"><div><span class="eyebrow">CASE-LOCAL EVIDENCE GRAPH</span><h2>Infrastructure relationships</h2><p>${graph.nodes.length} entities · ${graph.edges.length} sourced observations · collected ${esc(shortDate(record.result.generatedAt || record.updatedAt))}</p></div><button class="secondary-button" data-action="export-graphml">Export GraphML</button></div>
    <div class="notice graph-notice">Connections describe what a named source reported at collection time. They do not prove common ownership, identity, current control, or maliciousness. This graph uses infrastructure data from the selected case and makes no new network requests.</div>
    ${graph.omitted ? `<div class="notice">The graph is capped at 90 unique entities; ${graph.omitted} additional node candidate${graph.omitted === 1 ? " was" : "s were"} omitted. Other case views keep their normal results.</div>` : ""}
    <section class="panel relationship-graph-panel"><div class="relationship-toolbar"><label class="graph-search-field" for="relationship-search"><span>FIND AN ENTITY</span><input id="relationship-search" type="search" value="${esc(state.graphQuery)}" placeholder="Filter graph labels" autocomplete="off" /></label><label class="graph-filter-field" for="relationship-filter"><span>SHOW</span><select id="relationship-filter"><option value="all" ${state.graphTypeFilter === "all" ? "selected" : ""}>All entities</option><option value="host" ${state.graphTypeFilter === "host" ? "selected" : ""}>Hostnames</option><option value="ip" ${state.graphTypeFilter === "ip" ? "selected" : ""}>IP addresses</option><option value="record" ${state.graphTypeFilter === "record" ? "selected" : ""}>DNS / registry</option></select></label><label class="graph-filter-field" for="relationship-source"><span>PROVENANCE</span><select id="relationship-source"><option value="all" ${state.graphSourceFilter === "all" ? "selected" : ""}>All sources</option>${sources.map((source) => `<option value="${esc(source)}" ${state.graphSourceFilter === source ? "selected" : ""}>${esc(source)}</option>`).join("")}</select></label><label class="graph-zoom-field" for="relationship-zoom"><span>ZOOM <output id="graph-zoom-value">${state.graphZoom}%</output></span><input id="relationship-zoom" type="range" min="70" max="160" step="5" value="${state.graphZoom}" aria-label="Graph zoom" /></label><button class="text-button graph-zoom-reset" data-action="reset-graph-zoom">Reset zoom</button><span class="graph-scroll-hint">Scroll the canvas · select a node for evidence</span></div><div class="network-graph-wrap relationship-canvas"><svg class="relationship-svg" style="width:${zoomWidth}px;min-width:${zoomWidth}px" data-graph-width="${width}" viewBox="0 0 ${width} ${height}" role="group" aria-label="Infrastructure relationship graph for ${esc(record.result.entity?.value)}">${edges}${nodes}</svg></div><div class="relationship-legend"><span><i class="legend-root"></i>Case subject</span><span><i class="legend-host"></i>Hostname</span><span><i class="legend-ip"></i>IP address</span><span><i class="legend-record"></i>DNS / registry record</span></div><p class="graph-filter-empty" id="graph-filter-empty" hidden>No connections match these filters.</p></section>
    ${selected ? `<section class="panel graph-selection-panel" aria-live="polite"><div class="graph-selection-heading"><span><span class="eyebrow">SELECTED ENTITY</span><h3>${esc(selected.label)}</h3><p>${esc(selected.detail || selected.type)} · ${selectedEdges.length} linked observation${selectedEdges.length === 1 ? "" : "s"} · ${selectedSourceCount} named source label${selectedSourceCount === 1 ? "" : "s"}</p></span><div class="graph-selection-actions">${canPivotSelected ? `<button class="secondary-button" data-action="pivot-entity" data-pivot-query="${esc(selected.label)}">Use as new case subject</button>` : ""}<button class="text-button" data-action="clear-graph-selection">Clear selection</button></div></div>${selectedEvidence ? `<ul class="graph-evidence-list">${selectedEvidence}</ul>` : ""}</section>` : ""}
    <section class="panel graph-ledger-panel"><div class="panel-heading"><div><span class="eyebrow">TIME & PROVENANCE</span><h3>Evidence timeline</h3></div><span class="panel-caption">Reported dates and collection times are kept distinct</span></div>${timelineRows ? `<ol class="graph-timeline">${timelineRows}</ol>` : `<p class="empty-record">No dated observations were returned.</p>`}</section>
    <section class="panel graph-ledger-panel"><div class="panel-heading"><div><span class="eyebrow">SOURCE PROVENANCE</span><h3>Evidence ledger</h3></div><span class="panel-caption">${graph.edges.length} graph connection${graph.edges.length === 1 ? "" : "s"}</span></div><div class="panel table-panel"><table><thead><tr><th>From</th><th>Observation</th><th>To</th><th>Source</th><th>Collected</th></tr></thead><tbody>${ledger}</tbody></table></div></section>`;
}

function subdomainsContent(record) {
  const module = record.result.modules?.subdomains;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">⌘</span><h3>No host discovery run</h3><p>Passive hostname discovery is available for domain cases.</p></div>`;
  if (module.status === "error") return `<div class="empty-panel"><span class="empty-glyph">⌘</span><h3>Host discovery unavailable</h3><p>${esc(module.error || "No public source returned results.")}</p>${(module.providers || []).map((provider) => `<div class="notice warning-notice">${esc(provider.name)}: ${esc(provider.error || "Source unavailable.")}</div>`).join("")}</div>`;
  const hosts = module.hosts || [];
  return `<div class="tab-intro"><div><span class="eyebrow">PASSIVE DOMAIN FOOTPRINT</span><h2>Subdomain map</h2><p>${esc(module.totalFound ?? hosts.length)} scoped hosts · checked ${esc(shortDate(module.queriedAt))}</p></div></div>
    ${module.status === "partial" ? `<div class="notice warning-notice">Some selected sources did not return data. Results from successful sources remain available below.</div>` : ""}
    ${module.truncated ? `<div class="notice">At least one public source was capped, or more than 500 names were found. This case may contain a partial result set.</div>` : ""}
    <section class="panel graph-panel"><div class="panel-heading"><div><span class="eyebrow">CORRELATED HOSTS</span><h3>${esc(record.result.entity?.value)}</h3></div><span class="panel-caption">First 18 hosts shown in graph</span></div>${networkGraph(module, record.result.entity?.value)}</section>
    <div class="panel table-panel host-table"><table><thead><tr><th>Hostname</th><th>Public addresses</th><th>Sources</th><th>Last archived / seen</th></tr></thead><tbody>${hosts.map((host) => { const lastSeen = host.archiveDates?.["Common Crawl"] || host.observedDates?.["urlscan.io"]; return `<tr><td><code>${esc(host.name)}</code></td><td>${host.addresses?.length ? host.addresses.map((address) => `<code>${esc(address)}</code>`).join("<br />") : `<span class="muted" title="${esc((host.resolutionErrors || []).join(" · "))}">${host.resolutionAttempted ? host.resolutionStatus === "error" ? "Lookup failed" : host.resolutionStatus === "partial" ? "Partial DNS error" : "No public address returned" : "Not checked (limit 25)"}</span>`}</td><td>${(host.sources || []).map((source) => `<span class="tag">${esc(source)}</span>`).join(" ")}</td><td>${lastSeen ? esc(shortDate(lastSeen)) : "—"}</td></tr>`; }).join("") || `<tr><td colspan="4">No hostnames returned.</td></tr>`}</tbody></table></div>
    ${(module.providers || []).map((provider) => provider.status === "error" ? `<div class="notice warning-notice">${esc(provider.name)}: ${esc(provider.error || "Source unavailable.")}</div>` : "").join("")}
    ${sourceCards({ modules: { subdomains: module } })}`;
}

function accountsContent(record) {
  const module = record.result.modules?.accounts;
  if (!module || module.status === "error") return `<div class="empty-panel"><span class="empty-glyph">◎</span><h3>Account checks unavailable</h3><p>${esc(module?.error || "The profile check did not return results.")}</p></div>`;
  const sites = module.sites || [];
  const rows = sites.map((item) => `<tr><td>${esc(item.site)}</td><td><span class="tag">${esc(item.category)}</span></td><td><span class="account-status ${esc(item.status)}">${esc(item.status.replace("_", " "))}</span></td><td>${esc(item.evidence || "No rule explanation is available.")}</td><td>${item.url ? safeLink(item.url, "Open profile") : "—"}</td></tr>`).join("");
  return `<div class="tab-intro"><div><span class="eyebrow">SELF-AUDIT / PUBLIC PROFILE URLS</span><h2>Account footprint</h2><p>@${esc(module.handle)} · ${esc(module.checked)} bounded checks · ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "Profile rules and license")}</div>
    <div class="metrics-grid account-metrics"><article class="metric-card"><span class="metric-label">Possible matches</span><strong>${esc(module.found)}</strong><span class="metric-foot">Review these manually</span></article><article class="metric-card"><span class="metric-label">Not found</span><strong>${esc(module.notFound)}</strong><span class="metric-foot">Site-specific response rules</span></article><article class="metric-card"><span class="metric-label">Unknown</span><strong>${esc(module.unknown)}</strong><span class="metric-foot">Blocked or ambiguous responses</span></article><article class="metric-card"><span class="metric-label">Rule license</span><strong class="metric-word">${esc(module.license)}</strong><span class="metric-foot">Pinned catalog revision</span></article></div>
    <div class="notice warning-notice">${esc(module.notice)}</div><p class="import-footnote">Profile rules from pinned catalog revision ${esc(module.catalogRevision || "unknown")}.</p>
    <div class="panel table-panel"><table><thead><tr><th>Site</th><th>Category</th><th>Result</th><th>Rule evidence</th><th>Profile</th></tr></thead><tbody>${rows || `<tr><td colspan="5">No sites were checked.</td></tr>`}</tbody></table></div>
    ${sourceCards({ modules: { accounts: module } })}`;
}

function importedContent(record) {
  const modules = record.result.modules?.imports ?? [];
  return `<div class="tab-intro"><div><span class="eyebrow">REPORT INTERCHANGE</span><h2>Imported tool results</h2><p>JSON, JSONL/NDJSON, CSV, or plain hostname lists · out-of-scope and personal fields are discarded.</p></div></div>
    <section class="panel import-panel"><div class="panel-heading"><div><span class="eyebrow">NORMALIZE EXTERNAL EVIDENCE</span><h3>Bring tool results into this case</h3></div><span class="panel-caption">Local file · no tool is launched</span></div><p class="tool-copy">Load a Subfinder host list or structured output from Subfinder, theHarvester, Amass, SpiderFoot, or a compatible exporter. uwu-osint keeps only findings inside this case’s existing scope, merges duplicates, and preserves source labels and collection time.</p><div class="import-controls"><label class="sr-only" for="import-tool">Report type</label><select id="import-tool"><option value="Generic OSINT report">Generic OSINT report</option><option value="Subfinder export">Subfinder export</option><option value="theHarvester export">theHarvester export</option><option value="Amass export">Amass export</option><option value="SpiderFoot export">SpiderFoot export</option><option value="Domain report">Domain report</option><option value="Network inventory">Network inventory</option><option value="Certificate report">Certificate report</option></select><label class="file-picker">Choose report<input id="report-file" type="file" accept=".json,.jsonl,.csv,.txt,application/json,text/csv,text/plain" /></label><button class="secondary-button" data-action="import-report">Import to case</button></div><p class="import-footnote">Supports JSON, JSONL/NDJSON, CSV, and plain hostname lists. Email addresses, people, phones, usernames, credentials, and out-of-scope data are dropped. Maximum file size: 4 MB.</p></section>
    ${modules.length ? `<div class="import-list">${modules.map((item) => `<section class="panel imported-report"><div class="imported-report-heading"><div><span class="tag">${esc(item.tool)}</span><b>${item.findings.length} finding${item.findings.length === 1 ? "" : "s"}</b></div><span>${esc(shortDate(item.queriedAt))}</span></div><p class="import-provenance">${item.filename ? `File: ${esc(item.filename)} · ` : ""}${esc(item.inputRecords ?? "?")} input record${item.inputRecords === 1 ? "" : "s"} · ${esc(item.invalidLines ?? 0)} invalid line${item.invalidLines === 1 ? "" : "s"} · ${esc(item.duplicateFindings ?? 0)} duplicate finding${item.duplicateFindings === 1 ? "" : "s"}${item.truncatedRecords ? ` · ${esc(item.truncatedRecords)} input record${item.truncatedRecords === 1 ? "" : "s"} skipped by the 10,000-row limit` : ""}${item.omittedCandidates ? ` · ${esc(item.omittedCandidates)} matching candidate${item.omittedCandidates === 1 ? "" : "s"} omitted by the 2,000-finding limit` : ""}</p>${item.findings.length ? `<ul>${item.findings.slice(0, 500).map((finding) => `<li><span class="tag">${esc(finding.type)}</span><code>${esc(finding.value)}</code>${(finding.sources || []).slice(0, 3).map((source) => `<span class="tag">${esc(source)}</span>`).join("")}</li>`).join("")}</ul>` : `<p class="subtle-note">No in-scope hostname or IP findings were found in that report.</p>`}</section>`).join("")}</div>` : `<div class="empty-panel compact-empty"><h3>No imported reports yet</h3><p>Import JSON, JSONL/NDJSON, CSV, or a plain hostname list to add scoped findings to this case.</p></div>`}`;
}

function emailAuditContent(record) {
  const audit = record.result.modules?.emailAudit;
  if (!audit) return `<div class="empty-panel"><span class="empty-glyph">✉</span><h3>No email-domain audit</h3><p>Public DNS checks are available for an email’s domain.</p></div>`;
  const rows = [
    ["Domain", audit.domain], ["MX status", audit.mxStatus], ["SPF record status", audit.spfStatus], ["DMARC record status", audit.dmarcStatus],
  ];
  const records = [
    ["MX records", audit.mxRecords], ["SPF records", audit.spfRecords], ["DMARC records", audit.dmarcRecords],
  ];
  return `<div class="tab-intro"><div><span class="eyebrow">PUBLIC EMAIL-DOMAIN DNS</span><h2>Mail configuration</h2><p>Checked ${esc(shortDate(audit.queriedAt))} · full address is not queried</p></div>${safeLink(audit.source, "DNS provider")}</div>
    <div class="notice warning-notice">${esc(audit.notice || "Public domain records only. No mailbox, person, or account lookup is performed.")}</div>
    <section class="panel registration-details"><div class="detail-list">${rows.map(([key, value]) => `<div class="detail-row"><span>${esc(key)}</span><b>${esc(value || "Unknown")}</b></div>`).join("")}</div></section>
    <div class="record-grid">${records.map(([title, values]) => `<section class="panel record-panel"><div class="record-heading"><div><span class="record-type">DNS</span><h3>${title}</h3></div><span class="count-tag">${values?.length || 0}</span></div>${values?.length ? `<ul class="record-list">${values.map((item) => `<li><code>${esc(item.data)}</code>${item.ttl != null ? `<span>TTL ${esc(item.ttl)}s</span>` : ""}</li>`).join("")}</ul>` : `<div class="empty-record">No answer returned</div>`}</section>`).join("")}</div>
    ${audit.dmarcError ? `<div class="notice">DMARC query status: ${esc(audit.dmarcError)}</div>` : ""}${sourceCards(record.result)}`;
}

function phoneContent(record) {
  const result = record.result.modules?.phoneValidation;
  if (!result) return `<div class="empty-panel"><h3>Phone format details unavailable</h3><p>Refresh the case to run a local format check.</p></div>`;
  const valid = result.validShape === true;
  const displayedNumber = state.revealSensitive ? result.normalized : caseSubjectLabel(record);
  return `<div class="tab-intro"><div><span class="eyebrow">LOCAL VALIDATION</span><h2>Phone number format</h2><p>No external provider was contacted.</p></div><span class="status-badge ${valid ? "available" : "unavailable"}"><i></i>${valid ? "Syntax valid" : "Invalid format"}</span></div>
    <section class="panel registration-details"><div class="detail-list"><div class="detail-row"><span>Normalized value</span><b>${esc(displayedNumber)}</b></div><div class="detail-row"><span>Format</span><b>${esc(result.format)}</b></div><div class="detail-row"><span>Digit count</span><b>${esc(result.digitCount)}</b></div><div class="detail-row"><span>Network requested</span><b>No</b></div></div></section>
    <div class="notice warning-notice">${esc(result.notice)}</div>`;
}

function ptrContent(record) {
  const module = record.result.modules?.reverseDns;
  if (!module) return `<div class="empty-panel"><span class="empty-glyph">↩</span><h3>No reverse DNS collection</h3><p>PTR lookup is available for public IP address cases.</p></div>`;
  if (module.status !== "ok") return `<div class="empty-panel"><span class="empty-glyph">↩</span><h3>Reverse DNS unavailable</h3><p>${esc(module.error)}</p>${safeLink(module.source || "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "DNS provider")}</div>`;
  return `<div class="tab-intro"><div><span class="eyebrow">PUBLIC REVERSE LOOKUP</span><h2>PTR names</h2><p>${esc(module.address)} · ${esc(module.reverseName)} · checked ${esc(shortDate(module.queriedAt))}</p></div>${safeLink(module.source, "DNS provider")}</div>
    <div class="notice">${esc(module.notice)}</div>
    ${module.names?.length ? `<section class="panel record-panel"><ul class="record-list">${module.names.map((name) => `<li><code>${esc(name)}</code></li>`).join("")}</ul></section>` : `<div class="empty-panel compact-empty"><h3>No PTR answer returned</h3><p>This address range has no public reverse-DNS name for the queried address.</p></div>`}
    ${sourceCards({ modules: { reverseDns: module } })}`;
}

function toolsDirectory() {
  const cards = [
    { title: "Domain footprint", category: "PUBLIC INFRASTRUCTURE", detail: "Join DNS answers, registry data, certificate names, passive hostnames, historical crawls, and optional public scan records into one scoped view.", icon: "⌘" },
    { title: "Historical host index", category: "PASSIVE ARCHIVE", detail: "Search Common Crawl and, when configured, URLScan’s historical public scans for hostnames and observation dates. Archive dates are not proof that a host is currently live.", icon: "◷" },
    { title: "Account footprint", category: "SELF-AUDIT", detail: "Check a username you own across a bounded set of public profile URLs. Matches are candidates, not identity proof.", icon: "◎" },
    { title: "Email domain audit", category: "DOMAIN DNS", detail: "Review MX, SPF, and DMARC records from an email address, or enter email-domain:example.com to check a domain without storing a mailbox identifier.", icon: "✉" },
    { title: "Phone format check", category: "LOCAL VALIDATION", detail: "Normalize an international number to E.164 syntax locally without querying a subscriber, carrier, or location.", icon: "+" },
    { title: "File metadata", category: "LOCAL INSPECTION", detail: "Read common image, PDF, and Office metadata on this machine, including GPS and author fields.", icon: "▧" },
    { title: "Report workspace", category: "INTERCHANGE", detail: "Import common infrastructure reports, filter to the case scope, and discard personal and contact data.", icon: "⇧" },
    { title: "Cross-case graph", category: "CASE ANALYSIS", detail: "Merge matching infrastructure entities across saved cases, filter by source, review linked case evidence, and export GraphML.", icon: "⤳" },
    { title: "Case watch", category: "MONITORING", detail: "Opt in to hourly, six-hour, or daily passive refreshes for infrastructure cases while this browser tab is open.", icon: "◷" },
    { title: "Evidence reports", category: "REPORTING", detail: "Create a print-ready report with collection times, source outcomes, evidence, graph relationships, and optional notes.", icon: "▤" },
    { title: "Encrypted case exchange", category: "PORTABILITY", detail: "Protect case backups with a passphrase and AES-GCM before downloading or transferring them.", icon: "▣" },
  ];
  return `<section class="tool-intro"><div><span class="eyebrow">NATIVE RESEARCH MODULES</span><h2>One workspace for public signals.</h2><p>Each module works with bounded collection, source attribution, and results kept in the local case workspace.</p></div><div class="tool-count"><strong>${cards.length}</strong><span>built-in modules</span></div></section>
    ${caseTransferPanel()}
    <section class="tool-card-grid">${cards.map((card) => `<article class="panel integration-card"><div class="integration-top"><span class="integration-icon">${card.icon}</span><span class="integration-status ready"><i></i>READY</span></div><span class="eyebrow">${card.category}</span><h3>${card.title}</h3><p>${card.detail}</p><div class="integration-footer"><span>Built in</span></div></article>`).join("")}</section>
    ${sourceDirectoryPanel()}
    ${externalSourcesPanel()}
    <section class="panel tool-workbench"><div class="panel-heading"><div><span class="eyebrow">LOCAL FILE PRIVACY CHECK</span><h3>Inspect file metadata</h3></div><span class="panel-caption">JPEG · PNG · TIFF · PDF · DOCX</span></div>
      <p class="tool-copy">Choose a file you own or have permission to inspect. It is sent only to this machine's local app server, parsed in memory, and not saved.</p>
      <div class="file-audit-controls"><label class="file-picker">Choose local file<input id="metadata-file" type="file" accept=".jpg,.jpeg,.png,.tif,.tiff,.pdf,.docx,image/jpeg,image/png,image/tiff,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" ${state.metadataBusy ? "disabled" : ""} /></label><label class="scope-check-inline"><input type="checkbox" id="metadata-scope" ${state.metadataBusy ? "disabled" : ""} /><span class="custom-check"></span><span>This is my file or I have permission</span></label><button class="secondary-button" data-action="audit-metadata" ${state.metadataBusy ? "disabled" : ""}>${state.metadataBusy ? "Inspecting…" : "Inspect metadata"}</button></div>
      ${state.metadataResult ? metadataResults(state.metadataResult) : ""}
    </section>
    ${flashMessage()}`;
}

function sourceDirectoryPanel() {
  const sources = [
    { name: "OSINT Framework", category: "Directory", tier: "public", access: "Free directory · entry access varies", inputs: "Research topic or entity type", outputs: "Curated external tools and links", detail: "A searchable directory that groups public research resources by subject and workflow. It points to third-party tools; it does not collect results itself.", url: "https://osintframework.com/", icon: "⌘" },
    { name: "Subfinder", category: "Domain discovery", tier: "public", access: "Open-source CLI · some sources need API keys", inputs: "Authorized root domain", outputs: "Passive hostnames and optional source labels", detail: "A focused passive subdomain enumerator designed for speed. Its JSON output can retain the source list; active resolution and IP output are separate options.", url: "https://github.com/projectdiscovery/subfinder", icon: "⌁" },
    { name: "Common Crawl URL Index", category: "Historical web", tier: "public", access: "Free public archive index · bounded query", inputs: "Authorized root domain", outputs: "Archived page hostnames and capture dates", detail: "An optional built-in query of the latest public crawl index. Results show where pages were archived, not whether a host is currently online.", url: "https://index.commoncrawl.org/", icon: "◷" },
    { name: "urlscan.io Search API", category: "Historical web", tier: "account", access: "API key · account quotas and terms apply", inputs: "Authorized root domain", outputs: "Public scan hostnames and last observed times", detail: "An optional, read-only search of historical public scan records. It does not submit new scans. The domain is sent to URLScan when selected; API key is read from the local server environment.", url: "https://docs.urlscan.io/apis/urlscan-openapi/search", icon: "◷" },
    { name: "theHarvester", category: "Reconnaissance", tier: "public", access: "Open-source · source access varies", inputs: "Authorized domain or organization", outputs: "Hostnames, IPs, URLs, and other source findings", detail: "Collects findings across many source categories and records source outcomes. This app’s importer intentionally keeps only in-scope infrastructure fields.", url: "https://github.com/laramies/theHarvester", icon: "⌁" },
    { name: "Amass", category: "Domain discovery", tier: "public", access: "Open-source · data source access varies", inputs: "Root domain and selected collection mode", outputs: "Discovered names, source data, graph associations", detail: "Supports broad domain enumeration, source selection, passive mode, and a graph-oriented local data store. Active modes require explicit scope review.", url: "https://github.com/owasp-amass/amass/wiki/User-Guide", icon: "⤳" },
    { name: "SpiderFoot", category: "Automated OSINT", tier: "public", access: "Open-source · optional modules need provider access", inputs: "Authorized seed entity and selected modules", outputs: "Correlated module events and graph exports", detail: "Automates collection and correlation across configurable modules, with JSON, CSV, and graph export options. External module traffic and credentials remain controlled by SpiderFoot.", url: "https://github.com/smicallef/spiderfoot", icon: "⤳" },
    { name: "OSINT Industries", category: "Identity", tier: "commercial", access: "Account / API access · plan terms vary", inputs: "Email, phone, username, name, wallet", outputs: "Provider results, timelines, maps, exports", detail: "Advertises multi-identifier searches, account and timeline views, exports, and API access. Treat results as vendor output that needs independent review.", url: "https://www.osint.industries/", icon: "◎" },
    { name: "Maltego", category: "Link analysis", tier: "mixed", access: "Free and paid plans · access varies", inputs: "Entities and configured transforms", outputs: "Linked entity graphs and source data", detail: "Visual link-analysis software with transforms, connectors, and optional commercial data services for building and reviewing evidence graphs.", url: "https://www.maltego.com/pricing/", icon: "⌘" },
    { name: "Censys", category: "Infrastructure", tier: "mixed", access: "Free credits · paid plans / credits", inputs: "Domains, IPs, networks, certificates", outputs: "Internet host, service, and certificate records", detail: "Searches internet-facing hosts, services, domains, and certificates, with structured asset views and API options.", url: "https://www.censys.com/resources/pricing", icon: "⌁" },
    { name: "Shodan", category: "Infrastructure", tier: "account", access: "Account · some actions use credits", inputs: "Authorized IPs, domains, or search terms", outputs: "Observed ports, services, and banners", detail: "Searches observations about internet-connected devices, including service banners and exposed network services. Use it only for authorized asset review.", url: "https://www.shodan.io/", icon: "⌖" },
    { name: "VirusTotal", category: "Threat intelligence", tier: "mixed", access: "Public lookup · API tiers vary", inputs: "URLs, domains, IPs, file hashes", outputs: "Reports, detections, and infrastructure links", detail: "Provides threat-intelligence reports with security-vendor detections and infrastructure relationships. Check its data-sharing terms before submitting files or URLs.", url: "https://docs.virustotal.com/reference/overview", icon: "◈" },
    { name: "AlienVault OTX", category: "Threat intelligence", tier: "public", access: "Community service · account/API terms", inputs: "Domains, IPs, URLs, file hashes", outputs: "Indicators, community pulses, references", detail: "Threat-indicator and community pulse research. The existing shortcut opens a provider search; it does not import results.", url: "https://otx.alienvault.com/", icon: "◈" },
    { name: "GreyNoise", category: "Threat intelligence", tier: "mixed", access: "Limited community lookups · account/plan limits", inputs: "Public IPv4 address", outputs: "Scanner observations, classification, owner context", detail: "Community IP lookups report whether GreyNoise observed scanning activity and return basic classification and organization context. Higher limits and additional data depend on current account terms.", url: "https://docs.greynoise.io/docs/using-the-greynoise-community-api", icon: "◈" },
    { name: "SecurityTrails", category: "Infrastructure", tier: "commercial", access: "API key required · plan terms vary", inputs: "Hostname and DNS record type", outputs: "Historical A, AAAA, MX, NS, SOA, TXT records", detail: "Its API documents historical DNS records by hostname and type. This directory entry does not connect an API key or submit case data.", url: "https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1", icon: "◷" },
    { name: "OpenCorporates", category: "Business records", tier: "commercial", access: "Open-data terms or commercial API", inputs: "Company name or registry identifiers", outputs: "Company and legal-entity records", detail: "Company and legal-entity records with source provenance, plus API and bulk-data access under separate terms.", url: "https://opencorporates.com/plug-in-our-data/", icon: "▦" },
    { name: "Epieos", category: "Identity", tier: "account", access: "External service · access terms vary", inputs: "Email or phone, entered on provider site", outputs: "Provider account-related search results", detail: "A provider for email or phone related account research. uwu-osint opens it for manual entry and does not submit the subject.", url: "https://epieos.com/", icon: "◎" },
    { name: "ShadowDragon Horizon", category: "Investigation platform", tier: "commercial", access: "Enterprise platform · contact for access", inputs: "Public-source queries and supplied data", outputs: "Identity triage, link graphs, monitoring", detail: "An enterprise investigation platform advertising identity research, link analysis, API-driven collection, and ongoing monitoring across public sources.", url: "https://shadowdragon.io/platform/", icon: "⤳" },
    { name: "Social Links Crimewall", category: "Investigation platform", tier: "commercial", access: "Demo / commercial access · terms vary", inputs: "Public identifiers and connected data sources", outputs: "Structured results, graphs, maps, reports", detail: "An investigation platform advertising connected open-data sources, automated link analysis, and investigation views. Verify source coverage and current terms with the provider.", url: "https://sociallinks.io/products/sl-crimewall", icon: "⤳" },
    { name: "Academic Torrents", category: "Research data", tier: "public", access: "Public dataset catalog", inputs: "Research topic or dataset title", outputs: "Dataset metadata and shared data", detail: "A catalog for sharing research datasets. It is a dataset source, not an identity lookup or a built-in collector.", url: "https://academictorrents.com/", icon: "▤" },
  ];
  const categories = [...new Set(sources.map((source) => source.category))];
  return `<section class="panel source-directory-panel"><div class="panel-heading"><div><span class="eyebrow">PUBLIC PRODUCT MAP</span><h3>Research source guide</h3></div><span class="panel-caption" id="source-directory-count" aria-live="polite">${sources.length} tools and catalogs</span></div>
    <p class="tool-copy">A quick map of open-source projects, public directories, specialist platforms, and gated data services. Input/output descriptions summarize published features; links open independent products, not built-in integrations or endorsements. Check each provider’s current access, privacy, licensing, and terms.</p>
    <div class="source-directory-controls"><label class="external-query-field" for="source-directory-search"><span>SEARCH SOURCES</span><input id="source-directory-search" type="search" placeholder="Name, data type, or capability" autocomplete="off" /></label><label class="graph-filter-field" for="source-directory-category"><span>CATEGORY</span><select id="source-directory-category"><option value="all">All categories</option>${categories.map((category) => `<option value="${esc(category)}">${esc(category)}</option>`).join("")}</select></label><label class="graph-filter-field" for="source-directory-access"><span>ACCESS MODEL</span><select id="source-directory-access"><option value="all">All access types</option><option value="public">Public / open</option><option value="account">Account / credits</option><option value="commercial">Paid / commercial</option><option value="mixed">Free and paid</option></select></label></div>
    <div class="source-directory-grid">${sources.map((source) => `<article class="source-directory-card" data-source-card data-source-category="${esc(source.category)}" data-source-tier="${source.tier}"><div class="source-directory-card-top"><span class="integration-icon">${source.icon}</span><span class="tag">${esc(source.category)}</span></div><h4>${esc(source.name)}</h4><p>${esc(source.detail)}</p><div class="source-capabilities"><span><b>IN</b> ${esc(source.inputs)}</span><span><b>OUT</b> ${esc(source.outputs)}</span></div><div class="source-access">${esc(source.access)}</div>${safeLink(source.url, "Provider details")}</article>`).join("")}</div><p class="source-directory-empty" id="source-directory-empty" hidden>No sources match those filters.</p>
  </section>`;
}

function externalSourcesPanel() {
  const sources = [
    { id: "otx", name: "AlienVault OTX", detail: "Threat intelligence for domains, IP addresses, and URLs.", action: "Search indicator", icon: "◈" },
    { id: "epieos", name: "Epieos", detail: "Open Epieos for a manual email or phone search; the app does not submit the value.", action: "Open Epieos", icon: "◎" },
    { id: "opencorporates", name: "OpenCorporates", detail: "Search public company and registry records by name.", action: "Search companies", icon: "▦" },
    { id: "academictorrents", name: "Academic Torrents", detail: "Search the academic dataset catalogue.", action: "Search datasets", icon: "▤" },
  ];
  return `<section class="panel tool-workbench external-source-workbench">
    <div class="panel-heading"><div><span class="eyebrow">CONNECTED PUBLIC SOURCES</span><h3>Search external sources</h3></div><span class="panel-caption">Opens provider pages</span></div>
    <p class="tool-copy">Enter a query, confirm authorization, then open one provider. OTX, OpenCorporates, and Academic Torrents receive the query. Epieos opens without it so you can enter an email or phone manually there.</p>
    <div class="external-query-row">
      <label class="external-query-field" for="external-query"><span>SEARCH QUERY</span><input id="external-query" type="text" maxlength="300" value="${esc(state.externalQuery)}" placeholder="Domain, IP, email, company, or dataset topic" autocomplete="off" /></label>
      <label class="scope-check-inline external-scope"><input type="checkbox" id="external-scope" ${state.externalAuthorized ? "checked" : ""} /><span class="custom-check"></span><span>I’m authorized to send this query to the selected source</span></label>
      <label class="scope-check-inline otx-url-warning" id="otx-url-warning" ${hasSensitiveOtxUrlParts(state.externalQuery) ? "" : "hidden"}><input type="checkbox" id="otx-url-acknowledged" ${state.externalOtxUrlAcknowledged ? "checked" : ""} /><span class="custom-check"></span><span>The complete URL, including its path, query, and fragment, will be sent to OTX. Remove access tokens or private data first.</span></label>
    </div>
    <div class="external-source-grid">${sources.map((source) => `<article class="external-source-card"><div class="external-source-heading"><span class="integration-icon">${source.icon}</span><b>${source.name}</b></div><p>${source.detail}</p><button class="secondary-button" data-action="external-search" data-source="${source.id}">${source.action} <span aria-hidden="true">↗</span></button></article>`).join("")}</div>
    <p class="import-footnote">Only one source opens per click. Epieos searches are entered on its site; this app does not submit or automate those searches.</p>
  </section>`;
}

function hasSensitiveOtxUrlParts(value) {
  if (!/^https?:\/\//i.test(String(value || "").trim())) return false;
  try {
    const parsed = new URL(String(value).trim());
    return parsed.pathname !== "/" || Boolean(parsed.search) || Boolean(parsed.hash);
  } catch {
    return false;
  }
}

function externalSourceUrl(source, rawQuery, acknowledgeOtxUrlParts = false) {
  const query = rawQuery.trim();
  if (!query || query.length > 300) throw new Error("Enter a search query up to 300 characters.");
  if (source === "otx") {
    let kind = "domain";
    let value = query;
    if (/^https?:\/\//i.test(query)) {
      let parsed;
      try {
        parsed = new URL(query);
      } catch {
        throw new Error("Enter a valid domain, public IP, or URL for OTX.");
      }
      if (!parsed.hostname || !["http:", "https:"].includes(parsed.protocol)) throw new Error("Enter a valid domain, public IP, or URL for OTX.");
      if (parsed.username || parsed.password) throw new Error("OTX URL searches cannot include embedded credentials. Remove the username and password.");
      if (hasSensitiveOtxUrlParts(query) && !acknowledgeOtxUrlParts) {
        throw new Error("Confirm that the complete URL, including its path, query, and fragment, may be sent to OTX. Remove tokens or private data first.");
      }
      kind = "url";
    } else if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(query)) {
      if (query.split(".").some((octet) => Number(octet) > 255)) throw new Error("Enter a valid domain, public IP, or URL for OTX.");
      kind = "ip";
    } else if (query.includes(":")) {
      try { new URL(`http://[${query}]/`); kind = "ip"; } catch { throw new Error("Enter a valid domain, public IP, or URL for OTX."); }
    } else if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(query)) {
      throw new Error("Enter a valid domain, public IP, or URL for OTX.");
    }
    return `https://otx.alienvault.com/indicator/${kind}/${encodeURIComponent(value)}`;
  }
  if (source === "epieos") {
    const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query);
    const compactPhone = query.replace(/[\s().-]/g, "");
    const phone = /^\+[1-9]\d{1,14}$/.test(compactPhone);
    if (!email && !phone) throw new Error("Enter an email address or international phone number for a manual Epieos search.");
    return "https://epieos.com/?r=1";
  }
  if (source === "opencorporates") {
    const url = new URL("https://opencorporates.com/companies");
    url.searchParams.set("q", query);
    return url.href;
  }
  if (source === "academictorrents") {
    const url = new URL("https://academictorrents.com/browse.php");
    url.searchParams.set("search", query);
    return url.href;
  }
  throw new Error("Unknown external source.");
}

function metadataResults(result) {
  return `<div class="metadata-result"><div class="metadata-result-head"><div><span class="eyebrow">LOCAL FILE RESULT</span><b>${esc(result.filename)}</b><small>${result.fields.length} metadata field${result.fields.length === 1 ? "" : "s"} · ${esc(shortDate(result.queriedAt))}</small></div><span class="status-badge available"><i></i>Not saved</span></div><div class="metadata-fields">${result.fields.map((field) => `<div class="detail-row"><span>${esc(field.tag)}</span><b>${esc(Array.isArray(field.value) ? field.value.join(", ") : field.value)}</b></div>`).join("") || `<span class="subtle-note">This parser found no fields it recognizes. The file may still contain metadata outside the supported formats.</span>`}</div><p class="import-footnote">${esc(result.notice)}</p></div>`;
}

function contentFor(record) {
  if (state.tab === "graph") return relationshipGraphContent(record);
  if (state.tab === "history") return historyContent(record);
  if (state.tab === "accounts") return accountsContent(record);
  if (state.tab === "email") return emailAuditContent(record);
  if (state.tab === "phone") return phoneContent(record);
  if (state.tab === "ptr") return ptrContent(record);
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
    <button class="case-item ${record.id === state.selectedCaseId ? "active" : ""}" data-case-id="${esc(record.id)}" aria-pressed="${record.id === state.selectedCaseId}">
      <span class="case-avatar">${esc(caseSubjectLabel(record).slice(0, 1).toUpperCase())}</span>
      <span class="case-item-copy"><b>${esc(caseSubjectLabel(record))}</b><small>${esc((record.result.entity?.type || "subject").toUpperCase())} · ${esc(shortDate(record.updatedAt))}</small></span>
      <span class="case-arrow">›</span>
    </button>`).join("");
}

function caseSubjectLabel(record) {
  const entity = record.result?.entity || {};
  if (entity.type === "email") {
    const [local, domain] = String(entity.value || record.query || "").split("@", 2);
    return local && domain ? `${local.slice(0, 1)}•••@${domain}` : "••• email";
  }
  if (entity.type === "phone") {
    const value = String(entity.value || record.query || "");
    return value.length > 6 ? `${value.slice(0, 3)}••••${value.slice(-2)}` : "•••• phone";
  }
  if (entity.type === "email-domain") return `Email domain · ${entity.domain || entity.value || "domain"}`;
  return record.query || "Untitled case";
}

function subjectDisplayLabel(record) {
  const type = record?.result?.entity?.type;
  return state.revealSensitive && (type === "email" || type === "phone") ? record.query : caseSubjectLabel(record);
}

function updateAccountPreview() {
  const wrapper = document.querySelector("#profile-preview");
  const list = wrapper?.querySelector("ul");
  if (!wrapper || !list) return;
  list.replaceChildren();
  if (state.categoriesLoading && !state.accountPreview.length) {
    const item = document.createElement("li");
    item.textContent = "Loading the public profile list…";
    list.append(item);
  } else if (state.accountPreview.length) {
    for (const site of state.accountPreview) {
      const item = document.createElement("li");
      item.textContent = `${site.name} (${site.host})`;
      list.append(item);
    }
  } else {
    const item = document.createElement("li");
    item.textContent = "The profile list is unavailable; no username request has been made.";
    list.append(item);
  }
  const stale = wrapper.querySelector("[data-catalog-stale]");
  if (stale) stale.hidden = !state.accountPreviewStale;
  const revision = wrapper.querySelector("[data-catalog-revision]");
  if (revision) revision.textContent = state.accountPreviewRevision ? `Catalog revision ${state.accountPreviewRevision}` : "";
}

function updatePrivacyPreview(value) {
  const preview = document.querySelector("#privacy-preview");
  const checkedSources = [...document.querySelectorAll('input[name="domainSource"]:checked')].map((input) => input.value);
  const previewSources = document.querySelector("#domain-source-options")
    ? checkedSources
    : currentCase()?.collectionOptions?.domainSources || DEFAULT_DOMAIN_SOURCES;
  if (preview) preview.textContent = disclosureText(value, currentCase()?.result?.entity || {}, previewSources);
  const profilePreview = document.querySelector("#profile-preview");
  if (profilePreview) {
    profilePreview.hidden = !/^(?:@|username:)/i.test(String(value || "").trim());
    if (!profilePreview.hidden) updateAccountPreview();
  }
}

function summarizeResult(result) {
  const modules = result?.modules || {};
  const metrics = {};
  if (modules.dns) {
    const answers = Object.values(modules.dns.records || {}).reduce((total, rows) => total + (Array.isArray(rows) ? rows.length : 0), 0);
    metrics["DNS answers"] = String(answers);
    metrics["DNS status"] = modules.dns.status || "unknown";
  }
  if (modules.certificates) metrics["Certificate names"] = String(modules.certificates.names?.length ?? 0);
  if (modules.subdomains) metrics["Discovered hosts"] = `${modules.subdomains.totalFound ?? modules.subdomains.hosts?.length ?? 0} (${modules.subdomains.resolvedCount ?? 0} resolved)`;
  const urlscanProvider = modules.subdomains?.providers?.find((provider) => provider.id === "urlscan");
  if (urlscanProvider) metrics["URLScan public results"] = `${urlscanProvider.count ?? 0} · ${urlscanProvider.status || "unknown"}`;
  if (modules.registration) metrics["RDAP status"] = modules.registration.status || "unknown";
  if (modules.reverseDns) metrics["PTR names"] = String(modules.reverseDns.names?.length ?? 0);
  if (modules.accounts) metrics["Profile checks"] = `${modules.accounts.found ?? 0} possible · ${modules.accounts.notFound ?? 0} absent · ${modules.accounts.unknown ?? 0} unknown`;
  if (modules.emailAudit) metrics["Mail DNS"] = `MX ${modules.emailAudit.mxStatus} · SPF ${modules.emailAudit.spfStatus} · DMARC ${modules.emailAudit.dmarcStatus}`;
  if (modules.phoneValidation) metrics["Phone check"] = modules.phoneValidation.validShape ? "E.164 shape valid" : "Invalid shape";
  if (modules.imports?.length) metrics["Imported reports"] = String(modules.imports.length);
  return { generatedAt: result?.generatedAt || new Date().toISOString(), metrics };
}

function captureEvidenceSnapshot(result) {
  const modules = result?.modules || {};
  const evidence = new Map();
  const add = (type, value, source) => {
    if (!value || !source) return;
    const item = { type, value: String(value), source };
    evidence.set(`${type}\u0000${item.value.toLowerCase()}\u0000${source}`, item);
  };
  const certificateModule = modules.certificates || {};
  const hostModule = modules.subdomains || {};
  const hostProviders = hostModule.providers || [];
  const certificateProvider = hostProviders.find((item) => item.id === "crtsh");
  const hostSearchProvider = hostProviders.find((item) => item.id === "hackertarget");
  const commonCrawlProvider = hostProviders.find((item) => item.id === "commoncrawl");
  const urlscanProvider = hostProviders.find((item) => item.id === "urlscan");
  const sources = {
    "crt.sh": {
      status: certificateModule.status || certificateProvider?.status || "unknown",
      complete: certificateModule.status === "ok" && !certificateModule.truncated,
    },
    HackerTarget: {
      status: hostSearchProvider?.status || "unknown",
      complete: hostSearchProvider?.status === "ok" && !hostSearchProvider?.truncated && !hostModule.truncated,
    },
    "Common Crawl": {
      status: commonCrawlProvider?.status || "unknown",
      complete: commonCrawlProvider?.status === "ok" && !commonCrawlProvider?.truncated && !hostModule.truncated,
    },
    "urlscan.io": {
      status: urlscanProvider?.status || "unknown",
      complete: urlscanProvider?.status === "ok" && !urlscanProvider?.truncated && !hostModule.truncated,
    },
  };
  for (const certificate of certificateModule.names || []) add("Hostname", certificate.name, "crt.sh");
  for (const host of hostModule.hosts || []) {
    if ((host.sources || []).includes("HackerTarget")) add("Hostname", host.name, "HackerTarget");
    if ((host.sources || []).includes("Common Crawl")) add("Hostname", host.name, "Common Crawl");
    if ((host.sources || []).includes("urlscan.io")) add("Hostname", host.name, "urlscan.io");
  }
  const allEvidence = [...evidence.values()].sort((a, b) => a.source.localeCompare(b.source) || a.value.localeCompare(b.value));
  const limit = 2500;
  return {
    generatedAt: result?.generatedAt || new Date().toISOString(),
    evidence: allEvidence.slice(0, limit),
    sources,
    truncated: allEvidence.length > limit,
  };
}

function historyContent(record) {
  const history = Array.isArray(record.history) ? record.history : [];
  if (!history.length) return `<div class="empty-panel compact-empty"><h3>No earlier collection yet</h3><p>Refresh this case to save a compact summary and compare module counts with the previous run.</p></div>`;
  const latest = history[0];
  const current = summarizeResult(record.result);
  const keys = [...new Set([...Object.keys(latest.metrics || {}), ...Object.keys(current.metrics || {})])];
  const priorEvidence = latest.evidenceSnapshot;
  const currentEvidence = captureEvidenceSnapshot(record.result);
  const comparableSources = Object.keys(currentEvidence.sources).filter((source) =>
    priorEvidence?.sources?.[source]?.status === "ok" && priorEvidence.sources[source].complete === true
    && currentEvidence.sources[source].status === "ok" && currentEvidence.sources[source].complete === true
    && !priorEvidence.truncated && !currentEvidence.truncated);
  const evidenceKey = (item) => `${item.type}\u0000${String(item.value).toLowerCase()}\u0000${item.source}`;
  const priorKeys = new Set((priorEvidence?.evidence || []).map(evidenceKey));
  const currentKeys = new Set(currentEvidence.evidence.map(evidenceKey));
  const newlyObserved = currentEvidence.evidence.filter((item) => comparableSources.includes(item.source) && !priorKeys.has(evidenceKey(item)));
  const notReturned = (priorEvidence?.evidence || []).filter((item) => comparableSources.includes(item.source) && !currentKeys.has(evidenceKey(item)));
  const changeList = (items) => items.length
    ? `<ul class="evidence-delta-list">${items.slice(0, 30).map((item) => `<li><span class="tag">${esc(item.source)}</span><code>${esc(item.value)}</code></li>`).join("")}</ul>${items.length > 30 ? `<p class="import-footnote">${items.length - 30} more observation${items.length - 30 === 1 ? "" : "s"} not shown.</p>` : ""}`
    : `<p class="subtle-note">No comparable observations in this category.</p>`;
  return `<div class="tab-intro"><div><span class="eyebrow">REFRESH COMPARISON</span><h2>Collection history</h2><p>Latest saved snapshot ${esc(shortDate(latest.generatedAt))} · ${history.length} of 5 summaries retained</p></div></div>
    <div class="notice">Provider-level hostname changes compare only sources that succeeded in both runs with untruncated results. “Not returned” describes a changed result set; it does not prove a hostname was removed.</div>
    <div class="panel table-panel"><table><thead><tr><th>Module summary</th><th>Previous run</th><th>Current run</th></tr></thead><tbody>${keys.map((key) => `<tr><td>${esc(key)}</td><td>${esc(latest.metrics?.[key] ?? "—")}</td><td>${esc(current.metrics?.[key] ?? "—")}</td></tr>`).join("") || `<tr><td colspan="3">No comparable module summaries.</td></tr>`}</tbody></table></div>
    ${priorEvidence ? `<div class="history-delta-grid"><section class="panel history-delta-panel"><div class="panel-heading"><div><span class="eyebrow">SAME-SOURCE DIFF</span><h3>New observations</h3></div><span class="count-tag">${newlyObserved.length}</span></div>${changeList(newlyObserved)}</section><section class="panel history-delta-panel"><div class="panel-heading"><div><span class="eyebrow">SAME-SOURCE DIFF</span><h3>Not returned this run</h3></div><span class="count-tag">${notReturned.length}</span></div>${changeList(notReturned)}</section></div>` : `<div class="empty-panel compact-empty"><h3>Detailed comparisons start with the next refresh</h3><p>Older saved snapshots contain module counts only. Refresh this case to start tracking provider-specific hostname observations.</p></div>`}
    ${history.length > 1 ? `<section class="panel history-list"><div class="panel-heading"><div><span class="eyebrow">OLDER RUNS</span><h3>Recent snapshots</h3></div></div>${history.slice(1).map((snapshot, index) => `<div class="history-item"><b>Run ${index + 2}</b><time>${esc(shortDate(snapshot.generatedAt))}</time><span>${esc(Object.entries(snapshot.metrics || {}).map(([key, value]) => `${key}: ${value}`).join(" · ") || "No summary")}</span></div>`).join("")}</section>` : ""}`;
}

function tabButton(tab, title, icon, disabled = false) {
  return `<button class="result-tab ${state.tab === tab ? "active" : ""}" data-tab="${tab}" aria-pressed="${state.tab === tab}" aria-controls="result-view" ${disabled ? "disabled" : ""}><span aria-hidden="true">${icon}</span>${title}</button>`;
}

function flashMessage() {
  if (!state.flash) return "";
  const success = /^(Case updated\.|\d+ in-scope infrastructure finding|Opened |Monitoring |Infrastructure value staged|Imported \d+ encrypted case)/.test(state.flash);
  return `<div class="flash-message ${success ? "success" : "error"}" role="${success ? "status" : "alert"}">${esc(state.flash)}</div>`;
}

function render() {
  const record = currentCase();
  const entityType = record?.result?.entity?.type;
  const domain = entityType === "domain";
  const username = entityType === "username";
  const email = entityType === "email" || entityType === "email-domain";
  const phone = entityType === "phone";
  const sensitiveCase = entityType === "email" || phone;
  const ip = entityType === "ip";
  const graphEligible = ["domain", "email-domain", "ip", "asn"].includes(entityType);
  const inTools = state.view === "tools";
  const inCaseGraph = state.view === "case-graph";
  const initialQuery = !record ? state.pivotQuery
    : username ? `@${record.result.entity.value}`
      : sensitiveCase && !state.revealSensitive ? ""
        : record.query || "";
  const privacyQuery = initialQuery || record?.query || "";
  const savedDomainSources = Array.isArray(record?.collectionOptions?.domainSources)
    ? record.collectionOptions.domainSources
    : DEFAULT_DOMAIN_SOURCES;
  const showDomainSources = record?.result?.entity?.type === "domain" || likelyDomainLookup(privacyQuery);
  ROOT.innerHTML = `
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand-lockup"><div class="brand-mark">u<span>w</span></div><div><b>uwu<span>osint</span></b><small>PUBLIC SURFACE WORKSPACE</small></div></div>
        <div class="sidebar-rule"></div>
        <div class="side-label">WORKSPACE</div>
        <button class="side-link ${inTools ? "" : "selected"}" data-action="open-workspace"><span class="side-icon">▦</span>Research board${inTools ? "" : `<span class="nav-dot"></span>`}</button>
        <button class="side-link" data-action="new-case"><span class="side-icon">＋</span>New case</button>
        <button class="side-link ${inTools ? "selected" : ""}" data-action="open-tools"><span class="side-icon">⌘</span>Built-in modules${inTools ? `<span class="nav-dot"></span>` : ""}</button>
        <button class="side-link ${inCaseGraph ? "selected" : ""}" data-action="open-case-graph"><span class="side-icon">⤳</span>Case graph${inCaseGraph ? `<span class="nav-dot"></span>` : ""}</button>
        <div class="case-section-heading"><span class="side-label">RECENT CASES</span><span class="case-count">${state.cases.length}</span></div>
        <div class="case-list">${caseList()}</div>
        <div class="sidebar-bottom"><div class="local-indicator"><i></i><span>Local workspace</span></div><p>Cases are stored in this browser. No account required.</p>${state.cases.length ? `<button class="clear-cases-button" data-action="clear-cases">Clear saved cases</button>` : ""}<div class="version-label">UWU OSINT <span>0.1.0</span></div></div>
      </aside>
      <main class="main-content" id="main-content">
        <header class="topbar"><div class="breadcrumb"><span>Workspace</span><i>/</i><b>${inTools ? "Built-in modules" : inCaseGraph ? "Case graph" : "Research board"}</b></div><div class="topbar-actions"><button class="topbar-view-switch" data-action="${inTools || inCaseGraph ? "open-workspace" : "open-tools"}">${inTools || inCaseGraph ? "Research board" : "Built-in modules"}</button><span class="passive-label"><i></i>${!inTools && !inCaseGraph && phone ? "LOCAL FORMAT CHECK" : !inTools && !inCaseGraph && email ? "DOMAIN-ONLY SOURCE QUERIES" : "PUBLIC SOURCE QUERIES"}</span><div class="mobile-case-tools"><button class="mobile-case-graph ${inCaseGraph ? "active" : ""}" data-action="open-case-graph" title="Open case graph" aria-label="Open case graph">⤳</button>${!inTools && !inCaseGraph && state.cases.length ? `<label class="sr-only" for="mobile-case-select">Switch saved case</label><select id="mobile-case-select"><option value="" ${record ? "" : "selected"}>New case</option>${state.cases.map((item) => `<option value="${esc(item.id)}" ${item.id === record?.id ? "selected" : ""}>${esc(caseSubjectLabel(item))}</option>`).join("")}</select>` : ""}<button data-action="new-case">＋ New</button>${state.cases.length ? `<button class="mobile-clear-cases" data-action="clear-cases" aria-label="Clear all saved cases" title="Clear all saved cases">Clear</button>` : ""}</div>${record && !inTools && !inCaseGraph ? `<button class="icon-button" data-action="refresh-case" title="Refresh current case" aria-label="Refresh current case" ${state.busy ? "disabled" : ""}>↻</button><button class="icon-button" data-action="export-csv" title="Export evidence as CSV" aria-label="Export evidence as CSV">▤</button><button class="icon-button" data-action="export" title="Export current case as JSON" aria-label="Export current case as JSON">⇩</button>` : ""}</div></header>
        <div class="content-wrap">
          <section class="page-heading"><div><span class="eyebrow">${inTools ? "NATIVE RESEARCH MODULES" : inCaseGraph ? "CROSS-CASE ANALYSIS" : `INTELLIGENCE / ${record ? esc(record.result.entity?.type?.toUpperCase()) : "START HERE"}`}</span><h1>${inTools ? `Research <em>modules.</em>` : inCaseGraph ? `Case <em>graph.</em>` : `Public surface <em>research.</em>`}</h1><p>${inTools ? "Built-in collection, local file inspection, and report interchange." : inCaseGraph ? "Review infrastructure relationships across saved cases without making new provider requests." : "Research public infrastructure, self-audit accounts, check an email domain without storing a mailbox, and validate phone format locally."}</p></div><div class="heading-ornament"><div class="ornament-ring ring-one"></div><div class="ornament-ring ring-two"></div><div class="ornament-core">uwu</div></div></section>
          ${inTools || inCaseGraph ? "" : `<form class="search-panel" id="lookup-form"><div class="search-icon">⌕</div><div class="search-input-wrap"><label for="query">SUBJECT</label><input id="query" name="query" value="${esc(initialQuery)}" placeholder="Domain · IP · ASN · @username · email · email-domain:example.com · +14165550123" autocomplete="off" ${state.busy ? "disabled" : ""} /><div class="search-hint">Domain/URL · public IP · ASN · self-audit username · email · email-domain:example.com · E.164 phone format</div><div class="domain-source-options" id="domain-source-options" ${showDomainSources ? "" : "hidden"}><span class="domain-source-heading">PASSIVE HOST SOURCES</span><label><input type="checkbox" name="domainSource" value="crtsh" ${savedDomainSources.includes("crtsh") ? "checked" : ""} ${state.busy ? "disabled" : ""} /><span><b>Certificate transparency</b><small>Names in public certificate logs</small></span></label><label><input type="checkbox" name="domainSource" value="hackertarget" ${savedDomainSources.includes("hackertarget") ? "checked" : ""} ${state.busy ? "disabled" : ""} /><span><b>HackerTarget Host Search</b><small>Passive hostname and address results</small></span></label><label><input type="checkbox" name="domainSource" value="commoncrawl" ${savedDomainSources.includes("commoncrawl") ? "checked" : ""} ${state.busy ? "disabled" : ""} /><span><b>Common Crawl archive</b><small>Last seen in archived public pages</small></span></label><label><input type="checkbox" name="domainSource" value="urlscan" ${savedDomainSources.includes("urlscan") ? "checked" : ""} ${state.busy ? "disabled" : ""} /><span><b>urlscan.io historical scans</b><small>Public scan hostnames · local server API key required</small></span></label><p>Choose which providers receive the domain. URLScan is off by default and requires an API key. DNS and registration checks remain part of domain collection.</p></div><div class="account-filter" id="account-filter" ${username ? "" : "hidden"}><label for="account-category">PROFILE CATEGORY</label><select id="account-category" name="category" ${state.accountCategories.length ? "" : "disabled"}><option value="all">All categories</option>${state.accountCategories.map((item) => `<option value="${esc(item)}" ${state.accountCategory === item ? "selected" : ""}>${esc(item)}</option>`).join("")}</select></div></div><div class="search-divider"></div><div class="scope-check"><label><input type="checkbox" name="scope" ${state.busy ? "disabled" : ""} /><span class="custom-check"></span><span>I own this account, asset, or contact detail, or have permission to research it</span></label><button class="submit-button" type="submit" ${state.busy ? "disabled" : ""}>${state.busy ? `<span class="spinner"></span>Collecting` : `Investigate <span>↗</span>`}</button></div></form>${privacyDisclosure(record, privacyQuery)}`}
          ${inTools ? "" : flashMessage()}
          ${inTools ? toolsDirectory() : inCaseGraph ? workspaceGraphContent() : record ? `
            <section class="case-title-row"><div><div class="subject-line"><span class="subject-dot"></span><h2>${esc(subjectDisplayLabel(record))}</h2><span class="type-tag">${esc(record.result.entity?.type || "subject")}</span>${sensitiveCase ? `<button class="text-button reveal-subject-button" data-action="toggle-sensitive" aria-pressed="${state.revealSensitive}">${state.revealSensitive ? "Hide subject" : "Reveal subject"}</button>` : ""}</div><p>Case opened ${esc(shortDate(record.createdAt))} <span class="middle-dot">·</span> Latest collection ${esc(shortDate(record.result.generatedAt || record.updatedAt))}</p></div><div class="case-title-actions"><button class="secondary-button" data-action="print-report">Print report</button><button class="secondary-button" data-action="export-encrypted-case">Encrypted copy</button><button class="delete-button" data-action="delete-case">Delete case <span>×</span></button></div></section>
            <nav class="result-tabs" aria-label="Case views">${tabButton("overview", "Overview", "◫")}${username ? tabButton("accounts", "Account footprint", "◎") : ""}${email ? tabButton("email", "Email domain", "✉") : ""}${phone ? tabButton("phone", "Phone format", "+") : ""}${ip ? tabButton("ptr", "Reverse DNS", "↩") : ""}${domain || email ? tabButton("dns", "DNS records", "⌁") : ""}${domain ? tabButton("certificates", "Certificates", "▤") : ""}${domain ? tabButton("subdomains", "Subdomain map", "⌘") : ""}${graphEligible ? tabButton("graph", "Relationship graph", "⤳") : ""}${!username && !phone ? tabButton("registration", "Registration", "◈") : ""}${tabButton("imports", "Imported reports", "⇧")}${tabButton("history", "History", "◷")}</nav>
            <div class="result-content" id="result-view" role="region" aria-live="off" aria-label="${esc(state.tab)} results">${contentFor(record)}</div>
          ` : `<section class="welcome-grid"><article class="welcome-card"><div class="welcome-icon">⌁</div><span class="eyebrow">01 / COLLECT</span><h2>Start with a scoped subject</h2><p>Enter a domain or URL, public IP, ASN, username, email-domain check, or international phone number for an account or asset you may research.</p><div class="welcome-example"><span>TRY A FORMAT</span><code>iana.org · @handle · email-domain:iana.org</code></div></article><article class="welcome-card"><div class="welcome-icon">◈</div><span class="eyebrow">02 / CONNECT</span><h2>Keep the evidence together</h2><p>Each source reports independently. Findings include collection times, provider links, and a private case notebook.</p><div class="welcome-example"><span>CASE STORAGE</span><code>Only in this browser</code></div></article><article class="welcome-card"><div class="welcome-icon">⇩</div><span class="eyebrow">03 / EXPORT</span><h2>Take your work with you</h2><p>Save a case as JSON for your records or for later processing by another research tool.</p><div class="welcome-example"><span>EXPORT FORMAT</span><code>JSON · source-linked</code></div></article></section>
            <section class="getting-started"><div><span class="eyebrow">BUILT FOR CAREFUL RESEARCH</span><h3>Scoped source requests</h3><p>Infrastructure checks use public records. Account self-audits request public profile URLs without signing in.</p></div><div class="provider-chips"><span>Cloudflare DNS</span><span>IANA RDAP</span><span>crt.sh</span><span>Host Search</span></div></section>`}
          <footer class="page-footer"><span>UWU OSINT · LOCAL-FIRST RESEARCH</span><span>Public data can be incomplete or out of date. Verify important findings at their source. <a href="/terms.html">Terms</a> · <a href="/privacy.html">Privacy</a></span></footer>
        </div>
      </main>
    </div>`;
  if (username) {
    updateAccountPreview();
    populateAccountCategories();
  }
}

async function populateAccountCategories(category = state.accountCategory) {
  if ((state.accountCategories.length && state.accountPreviewCategory === category) || state.categoriesLoading) return;
  const requestId = ++state.accountPreviewRequest;
  state.categoriesLoading = true;
  state.accountPreview = [];
  state.accountPreviewStale = false;
  state.accountPreviewRevision = "";
  state.accountPreviewCategory = null;
  updateAccountPreview();
  try {
    const response = await fetch(`/api/account-categories?category=${encodeURIComponent(category)}`);
    const data = await response.json();
    if (!response.ok || !Array.isArray(data.categories)) return;
    if (requestId !== state.accountPreviewRequest) return;
    state.accountCategories = data.categories;
    state.accountPreview = Array.isArray(data.preview) ? data.preview : [];
    state.accountPreviewStale = data.catalogStale === true;
    state.accountPreviewRevision = String(data.catalogRevision || "");
    state.accountPreviewCategory = category;
    const select = document.querySelector("#account-category");
    if (select) {
      select.replaceChildren(new Option("All categories", "all"));
      for (const item of state.accountCategories) select.add(new Option(item, item));
      select.value = state.accountCategory;
      select.disabled = false;
    }
  } catch {
    // The default all-category lookup still works when the category list cannot load.
  } finally {
    if (requestId === state.accountPreviewRequest) {
      state.categoriesLoading = false;
      updateAccountPreview();
    }
  }
}

async function investigate(query, authorized, category = "all", existingCaseId = null, domainSources = null, background = false) {
  if (!background) state.revealSensitive = false;
  state.busy = true;
  if (!background) state.flash = "";
  render();
  try {
    const response = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, authorized, category, limit: 25, domainSources }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The lookup could not be completed.");
    const timestamp = data.generatedAt || new Date().toISOString();
    const entityType = data.entity?.type || "subject";
    const entityValue = String(data.entity?.value || query).toLowerCase();
    const record = state.cases.find((item) => item.id === existingCaseId)
      || state.cases.find((item) => item.result.entity?.type === entityType
        && String(item.result.entity?.value || "").toLowerCase() === entityValue);
    const displayQuery = entityType === "username" ? `@${data.entity.value}`
      : entityType === "email-domain" ? `email-domain:${data.entity.value}`
        : data.entity?.value || query;
    if (record) {
      const savedImports = record.result.modules?.imports || [];
      if (!Array.isArray(record.history)) record.history = [];
      const previousSnapshot = summarizeResult(record.result);
      previousSnapshot.evidenceSnapshot = captureEvidenceSnapshot(record.result);
      record.history.unshift(previousSnapshot);
      record.history = record.history.slice(0, 5);
      data.modules ||= {};
      if (savedImports.length) data.modules.imports = savedImports;
      record.query = displayQuery;
      record.updatedAt = timestamp;
      record.result = data;
      if (entityType === "domain") {
        record.collectionOptions = { ...(record.collectionOptions || {}), domainSources: data.modules.subdomains?.selectedSources || DEFAULT_DOMAIN_SOURCES };
      }
      if (background && record.monitor?.enabled) {
        record.monitor.lastRunAt = timestamp;
        record.monitor.lastError = "";
      }
      if (!background) state.flash = "Case updated. Your notes and imported reports were preserved.";
    } else {
      const newRecord = {
        id: globalThis.crypto?.randomUUID?.() || `case-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        query: displayQuery,
        createdAt: timestamp,
        updatedAt: timestamp,
        notes: "",
        result: data,
        ...(entityType === "domain" ? { collectionOptions: { domainSources: data.modules?.subdomains?.selectedSources || DEFAULT_DOMAIN_SOURCES } } : {}),
      };
      state.cases.unshift(newRecord);
      state.selectedCaseId = newRecord.id;
    }
    if (record && !background) state.selectedCaseId = record.id;
    if (!background) state.tab = "overview";
    state.pivotQuery = "";
    persistCases();
  } catch (error) {
    if (background) {
      const monitored = state.cases.find((item) => item.id === existingCaseId);
      if (monitored?.monitor?.enabled) monitored.monitor.lastError = error instanceof TypeError ? "Could not reach the local lookup server." : error.message;
      persistCases();
    } else {
      state.flash = error instanceof TypeError ? "Could not reach the local lookup server. Restart server.py and try again." : error.message;
    }
  } finally {
    state.busy = false;
    render();
  }
}

function updateCaseMonitor(enabled, intervalHours = null) {
  const record = currentCase();
  if (!record) return;
  const supported = ["domain", "email-domain", "ip", "asn"].includes(record.result?.entity?.type);
  if (!supported) return;
  if (enabled && !document.querySelector('[name="scope"]')?.checked) {
    state.flash = "Confirm authorization in the scope checkbox before enabling scheduled refresh.";
    render();
    document.querySelector('[name="scope"]')?.focus();
    return;
  }
  const hours = [1, 6, 24].includes(Number(intervalHours ?? record.monitor?.intervalHours))
    ? Number(intervalHours ?? record.monitor?.intervalHours) : 6;
  const timestamp = new Date().toISOString();
  record.monitor = {
    ...(record.monitor || {}),
    enabled,
    intervalHours: hours,
    nextRunAt: enabled ? new Date(Date.now() + hours * 60 * 60 * 1000).toISOString() : "",
    updatedAt: timestamp,
    lastError: "",
  };
  state.flash = enabled ? `Monitoring enabled. First refresh is due in ${hours} hour${hours === 1 ? "" : "s"}.` : "Monitoring disabled.";
  persistCases();
  armMonitorScheduler();
  render();
}

function updateMonitorInterval(intervalHours) {
  const record = currentCase();
  const hours = Number(intervalHours);
  if (!record?.monitor?.enabled || ![1, 6, 24].includes(hours)) return;
  record.monitor.intervalHours = hours;
  record.monitor.nextRunAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  record.monitor.lastError = "";
  persistCases();
  armMonitorScheduler();
  state.flash = `Monitoring updated. Next refresh is due in ${hours} hour${hours === 1 ? "" : "s"}.`;
  render();
}

function exportCase(record) {
  const content = JSON.stringify(record, null, 2);
  const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `uwu-osint-${caseSubjectLabel(record).replace(/[^a-z0-9.-]+/gi, "-")}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function exportEvidenceRows(record) {
  const modules = record.result.modules || {};
  const rows = [];
  const add = (type, value, source, collectedAt, details = "") => {
    if (value == null || value === "") return;
    rows.push({ type, value: String(value), source: String(source || "Source not recorded"), collectedAt: collectedAt || "", details: String(details || "") });
  };
  for (const [recordType, answers] of Object.entries(modules.dns?.records || {})) {
    for (const answer of Array.isArray(answers) ? answers : []) add(`DNS ${recordType}`, answer?.data, "Cloudflare DNS", modules.dns.queriedAt, answer?.ttl == null ? "" : `TTL ${answer.ttl}s`);
  }
  const audit = modules.emailAudit || {};
  for (const [label, status] of [["Email domain MX", audit.mxStatus], ["Email domain SPF", audit.spfStatus], ["Email domain DMARC", audit.dmarcStatus]]) add(label, status, "Cloudflare DNS", audit.queriedAt, "Public domain policy record status");
  const phone = modules.phoneValidation || {};
  if (phone.normalized) add("Phone format check", "Masked in report", "Local format check", phone.queriedAt, `${phone.format || "E.164"}; ${phone.digitCount} digits; no network request`);
  const registry = modules.registration || {};
  for (const [label, value] of [["Registry name", registry.name], ["Registry handle", registry.handle], ["Registry country", registry.country], ["Registry network type", registry.networkType]]) add(label, value, "IANA RDAP", registry.queriedAt);
  if (registry.startAddress || registry.endAddress) add("Registry address range", [registry.startAddress, registry.endAddress].filter(Boolean).join(" – "), "IANA RDAP", registry.queriedAt);
  for (const cidr of registry.cidrs || []) add("Registry CIDR", cidr, "IANA RDAP", registry.queriedAt);
  for (const nameserver of registry.nameservers || []) add("Registered nameserver", nameserver, "IANA RDAP", registry.queriedAt);
  for (const certificate of modules.certificates?.names || []) add("Certificate name", certificate.name, "crt.sh", modules.certificates.queriedAt, certificate.firstSeen ? `First seen ${certificate.firstSeen}` : "");
  for (const host of modules.subdomains?.hosts || []) {
    const providers = (host.sources || []).join(", ") || "Passive host discovery";
    const lastSeen = host.archiveDates?.["Common Crawl"] || host.observedDates?.["urlscan.io"];
    add("Subdomain", host.name, providers, modules.subdomains.queriedAt, lastSeen ? `Last archived / seen ${lastSeen}` : "");
    for (const address of host.addresses || []) add("Resolved address", address, providers, modules.subdomains.queriedAt, host.name);
  }
  for (const name of modules.reverseDns?.names || []) add("Reverse DNS name", name, "Cloudflare DNS", modules.reverseDns.queriedAt);
  for (const site of modules.accounts?.sites || []) add(`Profile ${site.status}`, site.url || site.site, "Public profile check", modules.accounts.queriedAt, [site.category, site.evidence].filter(Boolean).join("; "));
  for (const report of modules.imports || []) for (const finding of report.findings || []) add(`Imported ${finding.type}`, finding.value, [report.tool, ...(finding.sources || [])].filter(Boolean).join(" · "), report.queriedAt, "In-scope infrastructure finding");
  return rows.slice(0, 10_000);
}

function printCaseReport(record) {
  if (!record) return;
  const reportWindow = window.open("", "_blank");
  if (!reportWindow) {
    state.flash = "Allow a report window to open, then choose Print or Save as PDF.";
    render();
    return;
  }
  const sensitive = ["email", "phone"].includes(record.result.entity?.type);
  const includeFullSubject = sensitive && window.confirm("This case contains a private contact value. Include the full value in the report? Choose Cancel to keep it masked.");
  const includeNotes = Boolean(record.notes) && window.confirm("Include this case’s local working notes in the report?");
  const subject = includeFullSubject ? record.query : caseSubjectLabel(record);
  const evidence = exportEvidenceRows(record);
  const sources = sourcesFor(record.result);
  const graph = relationshipGraphData(record);
  const history = Array.isArray(record.history) ? record.history : [];
  const bodyRows = evidence.map((row) => `<tr><td>${esc(row.type)}</td><td><code>${esc(row.value)}</code></td><td>${esc(row.source)}</td><td>${esc(shortDate(row.collectedAt))}</td><td>${esc(row.details)}</td></tr>`).join("");
  const sourceRows = sources.map((source) => `<tr><td>${esc(source.name)}</td><td>${esc(source.module?.status || "unknown")}</td><td>${esc(shortDate(source.module?.queriedAt))}</td><td>${safeLink(sourceUrl(source), "Source record") || "—"}</td><td>${esc(source.module?.error || "")}</td></tr>`).join("");
  const graphRows = graph.edges.map((edge) => `<tr><td><code>${esc(edge.from.label)}</code></td><td>${esc(edge.label)}</td><td><code>${esc(edge.to.label)}</code></td><td>${esc(edge.source)}</td><td>${esc(shortDate(edge.queriedAt))}${edge.observedAt ? `<br>Observed ${esc(shortDate(edge.observedAt))}` : ""}</td></tr>`).join("");
  const noteSection = includeNotes ? `<section><h2>Working notes</h2><pre>${esc(record.notes)}</pre></section>` : "";
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>uwu-osint case report</title><style>
    :root{color-scheme:light;font:14px/1.5 Arial,sans-serif;color:#1c1b22;background:#fff}body{max-width:1080px;margin:40px auto;padding:0 28px}header{border-bottom:2px solid #6c58a6;padding-bottom:16px;margin-bottom:24px}h1{font-size:27px;margin:0 0 8px}h2{font-size:17px;margin:24px 0 9px}p,small{color:#555}dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 22px}dt{font-size:11px;text-transform:uppercase;color:#666}dd{margin:0;font-weight:600;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:11px}th,td{padding:7px 8px;text-align:left;vertical-align:top;border:1px solid #ddd;overflow-wrap:anywhere}th{background:#f2f0f6}code{font:11px ui-monospace,monospace;overflow-wrap:anywhere}a{color:#57428f}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:#f6f5f8;border:1px solid #ddd}.caveat{padding:12px;border-left:3px solid #8b6bd0;background:#f7f5fb}.actions{position:fixed;top:10px;right:12px}button{padding:8px 12px}@media print{body{max-width:none;margin:0;padding:0}.actions{display:none}section{break-inside:avoid}table{break-inside:auto}tr{break-inside:avoid}a{color:#222;text-decoration:none}}
    </style></head><body><div class="actions"><button onclick="window.print()">Print / Save as PDF</button></div><header><h1>uwu-osint · Case report</h1><p>Local evidence export · Generated ${esc(shortDate(new Date().toISOString()))}</p></header><section><h2>Case summary</h2><dl><div><dt>Subject</dt><dd>${esc(subject)}</dd></div><div><dt>Type</dt><dd>${esc(record.result.entity?.type || "subject")}</dd></div><div><dt>Case opened</dt><dd>${esc(shortDate(record.createdAt))}</dd></div><div><dt>Latest collection</dt><dd>${esc(shortDate(record.result.generatedAt || record.updatedAt))}</dd></div><div><dt>Refresh snapshots</dt><dd>${history.length}</dd></div><div><dt>Evidence rows</dt><dd>${evidence.length}</dd></div></dl></section><p class="caveat">Public-source observations can be incomplete, stale, or ambiguous. A graph connection is not proof of shared ownership, identity, current control, or maliciousness. Verify important evidence at its source.</p><section><h2>Source outcomes and provenance</h2><table><thead><tr><th>Source</th><th>Status</th><th>Collected</th><th>Provider</th><th>Notes</th></tr></thead><tbody>${sourceRows || `<tr><td colspan="5">No external sources were queried for this case.</td></tr>`}</tbody></table></section><section><h2>Evidence</h2><table><thead><tr><th>Type</th><th>Observation</th><th>Source</th><th>Collected</th><th>Details</th></tr></thead><tbody>${bodyRows || `<tr><td colspan="5">No exportable observations were returned.</td></tr>`}</tbody></table></section>${graphRows ? `<section><h2>Infrastructure relationships</h2><table><thead><tr><th>From</th><th>Observation</th><th>To</th><th>Source</th><th>Time</th></tr></thead><tbody>${graphRows}</tbody></table></section>` : ""}${noteSection}<footer><p>uwu-osint · local-first workspace · ${esc(record.id)}</p></footer></body></html>`;
  reportWindow.document.open();
  reportWindow.document.write(html);
  reportWindow.document.close();
  reportWindow.focus();
}

const CASE_BUNDLE_FORMAT = "uwu-osint-encrypted-case-bundle";
const CASE_BUNDLE_KDF_ITERATIONS = 250_000;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value, maximum = 12_000_000) {
  if (typeof value !== "string" || value.length > Math.ceil(maximum * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error("The encrypted case file is malformed or too large.");
  const binary = atob(value);
  if (binary.length > maximum) throw new Error("The encrypted case file is too large.");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveBundleKey(passphrase, salt) {
  const material = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: CASE_BUNDLE_KDF_ITERATIONS, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function downloadBlob(content, mimeType, filename) {
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportEncryptedBundle(records, filename) {
  if (!globalThis.crypto?.subtle) throw new Error("Encrypted export requires a secure browser context such as this local app at 127.0.0.1.");
  const first = window.prompt("Create a passphrase with at least 12 characters. The case subject, results, history, and notes will be encrypted.");
  if (first === null) return;
  if (first.length < 12) throw new Error("Use a passphrase with at least 12 characters.");
  const confirmPassphrase = window.prompt("Re-enter the passphrase. Keep it separate from the exported file; it cannot be recovered.");
  if (confirmPassphrase === null) return;
  if (first !== confirmPassphrase) throw new Error("The passphrases did not match.");
  const payload = JSON.stringify({ format: CASE_BUNDLE_FORMAT, version: 1, exportedAt: new Date().toISOString(), cases: records });
  const plaintext = new TextEncoder().encode(payload);
  if (plaintext.length > 10_000_000) throw new Error("This workspace is too large for one encrypted file. Export individual cases instead.");
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBundleKey(first, salt);
  const ciphertext = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const envelope = { format: CASE_BUNDLE_FORMAT, version: 1, kdf: "PBKDF2-SHA-256", iterations: CASE_BUNDLE_KDF_ITERATIONS, salt: bytesToBase64(salt), iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
  downloadBlob(JSON.stringify(envelope), "application/vnd.uwu-osint.encrypted+json", filename);
}

function validatePortableCase(value) {
  const allowedTypes = new Set(["domain", "email", "email-domain", "phone", "username", "ip", "asn"]);
  const isObject = (item) => Boolean(item && typeof item === "object" && !Array.isArray(item));
  const isStringList = (items) => items == null || (Array.isArray(items) && items.every((item) => typeof item === "string"));
  const isRecordList = (items, requiredStrings = []) => items == null || (Array.isArray(items) && items.every((item) => isObject(item) && requiredStrings.every((key) => typeof item[key] === "string")));
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.id !== "string" || value.id.length > 160
    || typeof value.query !== "string" || value.query.length > 300 || !value.result || typeof value.result !== "object"
    || !value.result.entity || !allowedTypes.has(value.result.entity.type) || typeof value.result.entity.value !== "string"
    || !value.result.modules || typeof value.result.modules !== "object" || Array.isArray(value.result.modules)) return false;
  const modules = value.result.modules;
  if (modules.dns && (!isObject(modules.dns) || !isObject(modules.dns.records) || Object.values(modules.dns.records).some((rows) => !Array.isArray(rows) || !isRecordList(rows, ["data"])) || !isStringList(modules.dns.errors))) return false;
  if (modules.emailAudit && (!isObject(modules.emailAudit) || ["mxRecords", "spfRecords", "dmarcRecords"].some((key) => modules.emailAudit[key] != null && !isRecordList(modules.emailAudit[key], ["data"])))) return false;
  if (modules.phoneValidation && !isObject(modules.phoneValidation)) return false;
  if (modules.reverseDns && (!isObject(modules.reverseDns) || !isStringList(modules.reverseDns.names))) return false;
  if (modules.certificates && (!isObject(modules.certificates) || !isRecordList(modules.certificates.names, ["name"]))) return false;
  if (modules.registration && (!isObject(modules.registration) || !isStringList(modules.registration.nameservers) || !isStringList(modules.registration.cidrs) || !isRecordList(modules.registration.events, ["action", "date"]))) return false;
  if (modules.accounts && (!isObject(modules.accounts) || !isRecordList(modules.accounts.sites, ["site", "status", "category"]))) return false;
  if (modules.subdomains && (!isObject(modules.subdomains) || !isRecordList(modules.subdomains.hosts, ["name"]) || !isRecordList(modules.subdomains.providers, ["id", "name", "status"])
    || modules.subdomains.hosts.some((host) => !isStringList(host.sources) || !isStringList(host.addresses) || !isStringList(host.resolutionErrors) || (host.archiveDates != null && !isObject(host.archiveDates)) || (host.observedDates != null && !isObject(host.observedDates))))) return false;
  if (modules.imports && (!Array.isArray(modules.imports) || modules.imports.some((item) => !isObject(item) || !Array.isArray(item.findings) || item.findings.some((finding) => !isObject(finding) || typeof finding.type !== "string" || typeof finding.value !== "string" || !isStringList(finding.sources))))) return false;
  if (typeof value.notes !== "string" && value.notes != null) return false;
  if (value.history != null && (!Array.isArray(value.history) || value.history.some((item) => !isObject(item) || (item.metrics != null && !isObject(item.metrics)) || (item.evidenceSnapshot != null && !isObject(item.evidenceSnapshot))))) return false;
  return true;
}

async function importEncryptedBundle(file) {
  if (!file) return;
  if (!globalThis.crypto?.subtle) throw new Error("Encrypted import requires a secure browser context such as this local app at 127.0.0.1.");
  if (file.size > 14_000_000) throw new Error("The encrypted case file is too large.");
  const envelope = JSON.parse(await file.text());
  if (!envelope || envelope.format !== CASE_BUNDLE_FORMAT || envelope.version !== 1 || envelope.kdf !== "PBKDF2-SHA-256" || envelope.iterations !== CASE_BUNDLE_KDF_ITERATIONS) throw new Error("This file is not a supported uwu-osint encrypted case bundle.");
  const salt = base64ToBytes(envelope.salt, 32);
  const iv = base64ToBytes(envelope.iv, 16);
  const ciphertext = base64ToBytes(envelope.ciphertext, 10_000_016);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) throw new Error("The encrypted case file is malformed.");
  const passphrase = window.prompt("Enter the passphrase for this encrypted case bundle.");
  if (passphrase === null) return;
  const key = await deriveBundleKey(passphrase, salt);
  let plaintext;
  try { plaintext = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext); }
  catch { throw new Error("Could not decrypt the file. Check the passphrase and file integrity."); }
  const payload = JSON.parse(new TextDecoder().decode(plaintext));
  if (!payload || payload.format !== CASE_BUNDLE_FORMAT || payload.version !== 1 || !Array.isArray(payload.cases) || payload.cases.length > 100 || !payload.cases.every(validatePortableCase)) throw new Error("The decrypted bundle does not contain valid uwu-osint cases.");
  if (!window.confirm(`Import ${payload.cases.length} case${payload.cases.length === 1 ? "" : "s"} into this browser? Existing cases will not be overwritten. Imported monitoring stays disabled.`)) return;
  const timestamp = new Date().toISOString();
  const capacity = Math.max(0, 500 - state.cases.length);
  if (!capacity) throw new Error("This browser already has the maximum of 500 saved cases. Delete or export some before importing.");
  const usedIds = new Set(state.cases.map((record) => record.id));
  const imported = payload.cases.slice(0, capacity).map((item) => {
    let id = item.id;
    if (usedIds.has(id)) id = `import-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
    usedIds.add(id);
    const intervalHours = [1, 6, 24].includes(Number(item.monitor?.intervalHours)) ? Number(item.monitor.intervalHours) : 6;
    return { ...item, id, importedAt: timestamp, monitor: { enabled: false, intervalHours, nextRunAt: "" } };
  });
  state.cases = [...imported, ...state.cases];
  state.selectedCaseId = imported[0]?.id || state.selectedCaseId;
  state.view = "workspace";
  state.tab = "overview";
  state.flash = `Imported ${imported.length} encrypted case${imported.length === 1 ? "" : "s"}. Review data and re-enable monitoring manually if needed.`;
  persistCases();
  render();
}

function caseTransferPanel() {
  return `<section class="panel case-transfer-panel"><div class="panel-heading"><div><span class="eyebrow">PRIVATE CASE EXCHANGE</span><h3>Encrypted backup and sharing</h3></div><span class="panel-caption">AES-GCM · local browser</span></div><p class="tool-copy">Export this browser’s cases to a passphrase-protected file for backup or transfer. The passphrase is never stored. Imported monitoring is disabled until you turn it on again.</p><div class="case-transfer-actions"><button class="secondary-button" data-action="export-encrypted-workspace" ${state.cases.length ? "" : "disabled"}>Export encrypted workspace</button><button class="secondary-button" data-action="import-encrypted-bundle">Import encrypted bundle</button><input id="case-bundle-file" type="file" accept=".uwucase,.json,application/json" hidden /></div><p class="import-footnote">Use a unique passphrase of at least 12 characters and share it through a separate channel. A lost passphrase cannot be recovered.</p></section>`;
}

function exportRelationshipGraph(record) {
  const graph = relationshipGraphData(record);
  if (!graph.edges.length) return;
  const xml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[character]);
  const nodeData = graph.nodes.map((node) => `<node id="${xml(node.id)}"><data key="label">${xml(node.label)}</data><data key="type">${xml(node.type)}</data><data key="detail">${xml(node.detail)}</data></node>`).join("");
  const edgeData = graph.edges.map((edge) => `<edge id="${xml(edge.id)}" source="${xml(edge.from.id)}" target="${xml(edge.to.id)}"><data key="observation">${xml(edge.label)}</data><data key="source">${xml(edge.source)}</data><data key="collected">${xml(edge.queriedAt)}</data><data key="observed">${xml(edge.observedAt)}</data><data key="detail">${xml(edge.detail)}</data></edge>`).join("");
  const content = `<?xml version="1.0" encoding="UTF-8"?><graphml xmlns="http://graphml.graphdrawing.org/xmlns"><key id="label" for="node" attr.name="label" attr.type="string"/><key id="type" for="node" attr.name="type" attr.type="string"/><key id="detail" for="all" attr.name="detail" attr.type="string"/><key id="observation" for="edge" attr.name="observation" attr.type="string"/><key id="source" for="edge" attr.name="source" attr.type="string"/><key id="collected" for="edge" attr.name="collected" attr.type="string"/><key id="observed" for="edge" attr.name="observed" attr.type="string"/><graph id="uwu-osint-case" edgedefault="directed">${nodeData}${edgeData}</graph></graphml>`;
  const url = URL.createObjectURL(new Blob([content], { type: "application/graphml+xml" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `uwu-osint-graph-${caseSubjectLabel(record).replace(/[^a-z0-9.-]+/gi, "-")}.graphml`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function exportWorkspaceGraph() {
  const graph = workspaceGraphData();
  if (!graph.edges.length) return;
  const xml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[character]);
  const nodes = graph.nodes.map((node) => `<node id="${xml(node.id)}"><data key="label">${xml(node.label)}</data><data key="type">${xml(node.type)}</data><data key="detail">${xml(node.detail)}</data><data key="cases">${xml([...node.caseIds].map((id) => caseSubjectLabel(state.cases.find((record) => record.id === id) || { query: id })).join("; "))}</data></node>`).join("");
  const edges = graph.edges.map((edge) => `<edge id="${xml(edge.id)}" source="${xml(edge.from.id)}" target="${xml(edge.to.id)}"><data key="observation">${xml(edge.label)}</data><data key="source">${xml(edge.source)}</data><data key="collected">${xml(edge.queriedAt)}</data><data key="observed">${xml(edge.observedAt)}</data><data key="case">${xml(edge.caseLabel)}</data><data key="detail">${xml(edge.detail)}</data></edge>`).join("");
  const content = `<?xml version="1.0" encoding="UTF-8"?><graphml xmlns="http://graphml.graphdrawing.org/xmlns"><key id="label" for="node" attr.name="label" attr.type="string"/><key id="type" for="node" attr.name="type" attr.type="string"/><key id="detail" for="all" attr.name="detail" attr.type="string"/><key id="cases" for="node" attr.name="cases" attr.type="string"/><key id="observation" for="edge" attr.name="observation" attr.type="string"/><key id="source" for="edge" attr.name="source" attr.type="string"/><key id="collected" for="edge" attr.name="collected" attr.type="string"/><key id="observed" for="edge" attr.name="observed" attr.type="string"/><key id="case" for="edge" attr.name="case" attr.type="string"/><graph id="uwu-osint-workspace" edgedefault="directed">${nodes}${edges}</graph></graphml>`;
  downloadBlob(content, "application/graphml+xml", "uwu-osint-workspace.graphml");
}

function filterSourceDirectory() {
  const query = document.querySelector("#source-directory-search")?.value.trim().toLowerCase() || "";
  const category = document.querySelector("#source-directory-category")?.value || "all";
  const access = document.querySelector("#source-directory-access")?.value || "all";
  const cards = [...document.querySelectorAll("[data-source-card]")];
  let visible = 0;
  for (const card of cards) {
    const matches = (category === "all" || card.dataset.sourceCategory === category)
      && (access === "all" || card.dataset.sourceTier === access)
      && (!query || card.textContent.toLowerCase().includes(query));
    card.hidden = !matches;
    if (matches) visible += 1;
  }
  const count = document.querySelector("#source-directory-count");
  if (count) count.textContent = `${visible} of ${cards.length} tools and catalogs`;
  const empty = document.querySelector("#source-directory-empty");
  if (empty) empty.hidden = visible !== 0;
}

function filterRelationshipGraph() {
  const query = document.querySelector("#relationship-search")?.value.trim().toLowerCase() || "";
  const kind = document.querySelector("#relationship-filter")?.value || "all";
  const source = document.querySelector("#relationship-source")?.value || "all";
  const nodes = [...document.querySelectorAll("[data-graph-node]")];
  const baseVisibility = new Map();
  for (const node of nodes) {
    const nodeKind = node.dataset.nodeKind;
    const matchesKind = kind === "all" || nodeKind === kind || (kind === "record" && nodeKind === "root");
    const matchesText = !query || node.dataset.nodeLabel?.includes(query);
    baseVisibility.set(node.dataset.graphNode, matchesKind && matchesText);
  }
  const edges = [...document.querySelectorAll("[data-edge-from]")];
  const visibleIds = new Set();
  const visibleEdges = new Set();
  for (const edge of edges) {
    if (source !== "all" && edge.dataset.edgeSource !== source) continue;
    const matchesBoth = baseVisibility.get(edge.dataset.edgeFrom) && baseVisibility.get(edge.dataset.edgeTo);
    const matchesEither = baseVisibility.get(edge.dataset.edgeFrom) || baseVisibility.get(edge.dataset.edgeTo);
    if (!(query || kind !== "all" ? matchesEither : matchesBoth)) continue;
    visibleIds.add(edge.dataset.edgeFrom);
    visibleIds.add(edge.dataset.edgeTo);
    visibleEdges.add(edge);
  }
  for (const node of nodes) node.style.display = visibleIds.has(node.dataset.graphNode) ? "" : "none";
  for (const edge of edges) edge.style.display = visibleEdges.has(edge) ? "" : "none";
  const rows = [...document.querySelectorAll("[data-ledger-from]")];
  for (const row of rows) row.hidden = !(visibleIds.has(row.dataset.ledgerFrom) && visibleIds.has(row.dataset.ledgerTo)
    && (source === "all" || row.dataset.ledgerSource === source));
  for (const row of document.querySelectorAll("[data-timeline-source], [data-evidence-source]")) {
    row.hidden = source !== "all" && row.dataset.timelineSource !== source && row.dataset.evidenceSource !== source;
  }
  const empty = document.querySelector("#graph-filter-empty");
  if (empty) empty.hidden = visibleEdges.size > 0;
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
  const emailAudit = modules.emailAudit || {};
  for (const [label, status] of [["Email domain MX", emailAudit.mxStatus], ["Email domain SPF", emailAudit.spfStatus], ["Email domain DMARC", emailAudit.dmarcStatus]]) {
    add(label, status, "Cloudflare DNS", emailAudit.queriedAt, "Public domain policy record status");
  }
  const phoneValidation = modules.phoneValidation || {};
  if (phoneValidation.normalized) {
    add("Phone format check", phoneValidation.normalized, "Local format check", phoneValidation.queriedAt, `${phoneValidation.format || "E.164"}; ${phoneValidation.digitCount} digits; no network request`);
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
    const archivedAt = host.archiveDates?.["Common Crawl"];
    const urlscanSeenAt = host.observedDates?.["urlscan.io"];
    add("Subdomain", host.name, providers, modules.subdomains.queriedAt, [archivedAt ? `Last archived ${archivedAt}` : "", urlscanSeenAt ? `Last seen in URLScan ${urlscanSeenAt}` : ""].filter(Boolean).join("; "));
    for (const address of host.addresses || []) add("Resolved address", address, providers, modules.subdomains.queriedAt, host.name);
  }
  for (const site of modules.accounts?.sites || []) {
    const details = [site.category, site.evidence, modules.accounts.catalogRevision ? `Catalog ${modules.accounts.catalogRevision}` : ""].filter(Boolean).join("; ");
    add(`Profile ${site.status}`, site.url || site.site, "Public profile check", modules.accounts.queriedAt, details);
  }
  for (const report of modules.imports || []) {
    for (const finding of report.findings || []) {
      const reportedSources = Array.isArray(finding.sources) ? finding.sources.join("; ") : "";
      const provenance = [report.tool || "Imported report", reportedSources].filter(Boolean).join(" · ");
      add(`Imported ${finding.type}`, finding.value, provenance, report.queriedAt, "In-scope infrastructure finding");
    }
  }

  const content = `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `uwu-osint-${caseSubjectLabel(record).replace(/[^a-z0-9.-]+/gi, "-")}-evidence.csv`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function parseCsv(text, stats = {}) {
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
      if (row.some((item) => item.trim())) {
        stats.totalCsvRecords = (stats.totalCsvRecords || 0) + 1;
        if (rows.length < 10001) rows.push(row);
        else stats.truncatedRecords = (stats.truncatedRecords || 0) + 1;
      }
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  row.push(field);
  if (row.some((item) => item.trim())) {
    stats.totalCsvRecords = (stats.totalCsvRecords || 0) + 1;
    if (rows.length < 10001) rows.push(row);
    else stats.truncatedRecords = (stats.truncatedRecords || 0) + 1;
  }
  if (quoted) stats.invalidLines = (stats.invalidLines || 0) + 1;
  const headers = (rows.shift() || []).map((item) => item.trim().toLowerCase());
  stats.inputRecords = Math.max(0, (stats.totalCsvRecords || 0) - (headers.length ? 1 : 0));
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
  const labels = candidate.split(".");
  if (labels.length < 2 || labels.some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || !/[a-z]/.test(labels.at(-1))) return null;
  if (scopeDomain && candidate !== scopeDomain && !candidate.endsWith(`.${scopeDomain}`)) return null;
  if (!scopeDomain) return null;
  if (/email|person|phone|user|account|address|contact|credential|leak/.test(typeHint)) return null;
  return { type: "HOST", value: candidate };
}

function sourceLabelsFrom(value) {
  const labels = [];
  for (const key of ["source", "sources", "provider", "providers", "module"]) {
    const item = value?.[key];
    const candidates = typeof item === "string" ? [item] : Array.isArray(item) ? item : [];
    for (const candidate of candidates) {
      if (typeof candidate !== "string") continue;
      const label = candidate.trim();
      if (label && label.length <= 120) labels.push(label);
    }
  }
  return [...new Set(labels)].slice(0, 8);
}

function collectInfrastructure(value, scope, output, hint = "", stats = { omittedCandidates: 0 }, inheritedSources = []) {
  if (value == null) return;
  if (Array.isArray(value)) {
    for (const item of value) collectInfrastructure(item, scope, output, hint, stats, inheritedSources);
    return;
  }
  if (!value || typeof value !== "object") return;
  const typeHint = String(value.type || value.eventType || value.event_type || value.kind || hint).toLowerCase();
  if (/email|person|phone|username|social|contact|credential|breach|password/.test(typeHint)) return;
  const sourceLabels = [...new Set([...inheritedSources, ...sourceLabelsFrom(value)])].slice(0, 8);
  const ipKeys = new Set(["ip", "ip_address", "ipaddress", "ipv4", "ipv6", "address_ip"]);
  const hostKeys = new Set(["host", "hostname", "domain", "subdomain", "fqdn", "internet_name", "name_value"]);
  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[ -]/g, "_");
    const candidateHint = `${typeHint} ${normalizedKey}`;
    const typedName = normalizedKey === "name" && /fqdn|host|domain|dns|internet_name/.test(typeHint);
    const typedValue = normalizedKey === "value" && /(^|[^a-z])(host|hostname|domain|subdomain|fqdn|internet_name|ip|ipv4|ipv6|ip_address)([^a-z]|$)/.test(typeHint);
    if (typeof child === "string" && (ipKeys.has(normalizedKey) || hostKeys.has(normalizedKey) || typedName || typedValue || (normalizedKey === "data" && /host|domain|internet_name|ip_address/.test(typeHint)))) {
      const finding = normalizedFinding(child, candidateHint, scope);
      if (finding) {
        if (output.length < 2000) output.push(sourceLabels.length ? { ...finding, sources: sourceLabels } : finding);
        else stats.omittedCandidates += 1;
      }
    }
    if (typeof child === "object") collectInfrastructure(child, scope, output, typeHint, stats, sourceLabels);
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
    state.flash = "Choose a JSON, JSONL, CSV export, or plain hostname list to import.";
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
    const importStats = { omittedCandidates: 0, invalidLines: 0, inputRecords: 0, truncatedRecords: 0 };
    if (file.name.toLowerCase().endsWith(".txt")) {
      const lines = text.split(/\r?\n/).filter((line) => line.trim());
      importStats.truncatedRecords = Math.max(0, lines.length - 10000);
      importStats.inputRecords = Math.min(lines.length, 10000);
      for (const line of lines.slice(0, 10000)) {
        const finding = normalizedFinding(line, "hostname", scope);
        if (finding) {
          if (findings.length < 2000) findings.push(finding);
          else importStats.omittedCandidates += 1;
        } else importStats.invalidLines += 1;
      }
    } else if (file.name.toLowerCase().endsWith(".csv")) {
      const rows = parseCsv(text, importStats);
      collectInfrastructure(rows, scope, findings, "", importStats);
    } else if (file.name.toLowerCase().endsWith(".jsonl")) {
      const parsed = [];
      const lines = text.split(/\r?\n/).filter((item) => item.trim());
      importStats.truncatedRecords = Math.max(0, lines.length - 10000);
      for (const line of lines.slice(0, 10000)) {
        try { parsed.push(JSON.parse(line)); } catch { importStats.invalidLines += 1; }
      }
      importStats.inputRecords = parsed.length;
      collectInfrastructure(parsed, scope, findings, "", importStats);
    } else {
      const parsed = JSON.parse(text);
      importStats.inputRecords = Array.isArray(parsed) ? parsed.length : parsed && typeof parsed === "object" ? 1 : 0;
      collectInfrastructure(parsed, scope, findings, "", importStats);
    }
    const uniqueByFinding = new Map();
    for (const item of findings) {
      const key = `${item.type}:${item.value}`;
      const existing = uniqueByFinding.get(key);
      const sources = [...new Set([...(existing?.sources || []), ...(item.sources || [])])].slice(0, 8);
      uniqueByFinding.set(key, { ...existing, ...item, ...(sources.length ? { sources } : {}) });
    }
    const unique = Array.from(uniqueByFinding.values());
    importStats.duplicateFindings = findings.length - unique.length;
    const tool = document.querySelector("#import-tool")?.value || "Imported tool";
    if (!record.result.modules.imports) record.result.modules.imports = [];
    record.result.modules.imports.push({
      status: "ok",
      tool,
      filename: file.name,
      source: "Local report import",
      queriedAt: new Date().toISOString(),
      findings: unique,
      inputRecords: importStats.inputRecords,
      invalidLines: importStats.invalidLines,
      duplicateFindings: importStats.duplicateFindings,
      omittedCandidates: importStats.omittedCandidates,
      truncatedRecords: importStats.truncatedRecords,
      droppedPersonalFields: true,
    });
    record.updatedAt = new Date().toISOString();
    state.flash = `${unique.length} in-scope infrastructure finding${unique.length === 1 ? "" : "s"} imported from ${tool}.`;
    persistCases();
    render();
  } catch {
    state.flash = "Could not parse that report. Choose valid JSON, JSONL, CSV, or plain hostname-list data.";
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
  state.metadataResult = null;
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
    state.flash = "Enter a domain or URL, public IP, ASN, @username, email, email-domain:example.com, or international phone number to start.";
    render();
    document.querySelector("#query")?.focus();
    return;
  }
  if (!form.get("scope")) {
    state.flash = "Confirm you own the account, asset, or contact detail, or have permission to research it.";
    render();
    document.querySelector("[name=scope]")?.focus();
    return;
  }
  const domainSources = form.getAll("domainSource").map(String);
  if (likelyDomainLookup(query) && domainSources.length === 0) {
    state.flash = "Select at least one passive hostname source for a domain lookup.";
    render();
    document.querySelector('input[name="domainSource"]')?.focus();
    return;
  }
  investigate(query, true, category, null, domainSources);
});

ROOT.addEventListener("click", (event) => {
  const caseButton = event.target.closest("[data-case-id]");
  if (caseButton) {
    state.view = "workspace";
    state.selectedCaseId = caseButton.dataset.caseId;
    state.revealSensitive = false;
    state.graphSelection = "";
    state.graphQuery = "";
    state.graphTypeFilter = "all";
    state.graphSourceFilter = "all";
    state.tab = "overview";
    state.flash = "";
    render();
    return;
  }
  const tabButton = event.target.closest("[data-tab]");
  if (tabButton && !tabButton.disabled) {
    state.tab = tabButton.dataset.tab;
    if (state.tab === "graph") state.graphSelection = "";
    render();
    return;
  }
  const graphNode = event.target.closest("[data-graph-node]");
  if (graphNode) {
    state.graphSelection = graphNode.dataset.graphNode;
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
  } else if (action === "open-case-graph") {
    state.view = "case-graph";
    state.graphSelection = "";
    state.graphQuery = "";
    state.graphTypeFilter = "all";
    state.graphSourceFilter = "all";
    state.flash = "";
    render();
  } else if (action === "open-workspace") {
    state.view = "workspace";
    state.flash = "";
    render();
  } else if (action === "new-case") {
    state.view = "workspace";
    state.selectedCaseId = null;
    state.pivotQuery = "";
    state.revealSensitive = false;
    state.graphSelection = "";
    state.graphQuery = "";
    state.graphTypeFilter = "all";
    state.graphSourceFilter = "all";
    state.tab = "overview";
    state.flash = "";
    render();
    document.querySelector("#query")?.focus();
  } else if (action === "clear-cases") {
    if (!state.cases.length || !window.confirm(`Clear all ${state.cases.length} saved case${state.cases.length === 1 ? "" : "s"} from this browser? This also deletes their notes and imported reports.`)) return;
    state.cases = [];
    state.selectedCaseId = null;
    state.revealSensitive = false;
    state.tab = "overview";
    state.flash = "";
    persistCases();
    render();
  } else if (action === "export") {
    const record = currentCase();
    if (record) exportCase(record);
  } else if (action === "export-csv") {
    const record = currentCase();
    if (record) exportEvidenceCsv(record);
  } else if (action === "print-report") {
    printCaseReport(currentCase());
  } else if (action === "export-encrypted-case") {
    const record = currentCase();
    if (record) exportEncryptedBundle([record], `uwu-osint-${caseSubjectLabel(record).replace(/[^a-z0-9.-]+/gi, "-")}.uwucase`).catch((error) => { state.flash = error.message; render(); });
  } else if (action === "export-encrypted-workspace") {
    exportEncryptedBundle(state.cases, "uwu-osint-workspace.uwucase").catch((error) => { state.flash = error.message; render(); });
  } else if (action === "import-encrypted-bundle") {
    document.querySelector("#case-bundle-file")?.click();
  } else if (action === "pivot-entity") {
    const query = String(actionButton.dataset.pivotQuery || "").trim();
    if (!query || query.length > 253) return;
    state.view = "workspace";
    state.selectedCaseId = null;
    state.pivotQuery = query;
    state.revealSensitive = false;
    state.graphSelection = "";
    state.graphQuery = "";
    state.tab = "overview";
    state.flash = "Infrastructure value staged as a new case. Review the source evidence and confirm authorization before querying.";
    render();
    document.querySelector("#query")?.focus();
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
    const domainSources = record.result.entity?.type === "domain"
      ? record.collectionOptions?.domainSources || DEFAULT_DOMAIN_SOURCES
      : [];
    investigate(record.query, true, category, record.id, domainSources);
  } else if (action === "delete-case") {
    const record = currentCase();
    if (!record || !window.confirm(`Delete the local case for ${caseSubjectLabel(record)}?`)) return;
    state.cases = state.cases.filter((item) => item.id !== record.id);
    state.selectedCaseId = state.cases[0]?.id ?? null;
    state.revealSensitive = false;
    state.graphSelection = "";
    state.graphQuery = "";
    state.graphTypeFilter = "all";
    state.graphSourceFilter = "all";
    state.tab = "overview";
    persistCases();
    render();
  } else if (action === "import-report") {
    importReport();
  } else if (action === "audit-metadata") {
    inspectLocalFile();
  } else if (action === "external-search") {
    const query = document.querySelector("#external-query")?.value || state.externalQuery;
    const authorized = document.querySelector("#external-scope")?.checked;
    if (!authorized) {
      state.flash = "Confirm authorization before sending this query to an external source.";
    } else {
      try {
        const source = actionButton.dataset.source;
        const sourceNames = { otx: "AlienVault OTX", epieos: "Epieos", opencorporates: "OpenCorporates", academictorrents: "Academic Torrents" };
        const url = externalSourceUrl(source, query, document.querySelector("#otx-url-acknowledged")?.checked === true);
        window.open(url, "_blank", "noopener,noreferrer");
        state.flash = source === "epieos"
          ? "Opened Epieos. Enter the email or phone there manually; this app does not submit or save it."
          : `Opened ${sourceNames[source]} in a new tab. The provider receives the query; results are not saved here.`;
      } catch (error) {
        state.flash = error.message;
      }
    }
    render();
  } else if (action === "export-graphml") {
    const record = currentCase();
    if (record) exportRelationshipGraph(record);
  } else if (action === "export-workspace-graph") {
    exportWorkspaceGraph();
  } else if (action === "clear-graph-selection") {
    state.graphSelection = "";
    render();
  } else if (action === "reset-graph-zoom") {
    state.graphZoom = 100;
    render();
  } else if (action === "toggle-sensitive") {
    state.revealSensitive = !state.revealSensitive;
    render();
  }
});

ROOT.addEventListener("input", (event) => {
  if (event.target.matches("#source-directory-search")) {
    filterSourceDirectory();
    return;
  }
  if (event.target.matches("#relationship-search")) {
    state.graphQuery = event.target.value;
    filterRelationshipGraph();
    return;
  }
  if (event.target.matches("#relationship-zoom")) {
    state.graphZoom = Math.max(70, Math.min(160, Number(event.target.value) || 100));
    const svg = document.querySelector(".relationship-svg");
    if (svg) {
      const width = Math.round(Number(svg.dataset.graphWidth) * state.graphZoom / 100);
      svg.style.width = `${width}px`;
      svg.style.minWidth = `${width}px`;
    }
    const output = document.querySelector("#graph-zoom-value");
    if (output) output.value = `${state.graphZoom}%`;
    return;
  }
  if (event.target.matches("#external-query")) {
    state.externalQuery = event.target.value;
    state.externalOtxUrlAcknowledged = false;
    const warning = document.querySelector("#otx-url-warning");
    if (warning) warning.hidden = !hasSensitiveOtxUrlParts(state.externalQuery);
    const checkbox = document.querySelector("#otx-url-acknowledged");
    if (checkbox) checkbox.checked = false;
    return;
  }
  if (event.target.matches("#query")) {
    const value = event.target.value.trim();
    const isUsername = /^(?:@|username:)/i.test(value);
    const filter = document.querySelector("#account-filter");
    if (filter) filter.hidden = !isUsername;
    const domainOptions = document.querySelector("#domain-source-options");
    if (domainOptions) domainOptions.hidden = !likelyDomainLookup(value) && currentCase()?.result?.entity?.type !== "domain";
    updatePrivacyPreview(value);
    if (isUsername) populateAccountCategories();
    return;
  }
  if (!event.target.matches("[data-notes]")) return;
  const record = currentCase();
  if (!record) return;
  record.notes = event.target.value;
  record.noteUpdatedAt = new Date().toISOString();
  persistCases();
  const saved = document.querySelector("[data-notes-saved]");
  if (saved) saved.textContent = "Saved in this browser";
});

ROOT.addEventListener("change", (event) => {
  if (event.target.matches("[data-monitor-toggle]")) {
    updateCaseMonitor(event.target.checked);
    return;
  }
  if (event.target.matches("[data-monitor-interval]")) {
    updateMonitorInterval(event.target.value);
    return;
  }
  if (event.target.matches("#case-bundle-file")) {
    const [file] = event.target.files || [];
    if (file) importEncryptedBundle(file).catch((error) => { state.flash = error instanceof SyntaxError ? "The selected file is not a valid encrypted bundle." : error.message; render(); });
    event.target.value = "";
    return;
  }
  if (event.target.matches('input[name="domainSource"]')) {
    updatePrivacyPreview(document.querySelector("#query")?.value.trim() || "");
  }
  if (event.target.matches("#source-directory-category, #source-directory-access")) filterSourceDirectory();
  if (event.target.matches("#relationship-filter")) {
    state.graphTypeFilter = event.target.value;
    filterRelationshipGraph();
  }
  if (event.target.matches("#relationship-source")) {
    state.graphSourceFilter = event.target.value;
    filterRelationshipGraph();
  }
  if (event.target.matches("#account-category")) {
    state.accountCategory = event.target.value;
    state.accountPreviewCategory = null;
    populateAccountCategories(state.accountCategory);
  }
  if (event.target.matches("#external-scope")) state.externalAuthorized = event.target.checked;
  if (event.target.matches("#otx-url-acknowledged")) state.externalOtxUrlAcknowledged = event.target.checked;
  if (event.target.matches("#mobile-case-select")) {
    state.selectedCaseId = event.target.value || null;
    state.revealSensitive = false;
    state.graphSelection = "";
    state.graphQuery = "";
    state.graphTypeFilter = "all";
    state.graphSourceFilter = "all";
    state.tab = "overview";
    state.flash = "";
    render();
  }
  if (event.target.matches("#metadata-file")) {
    state.metadataResult = null;
    state.flash = "";
    document.querySelector(".metadata-result")?.remove();
    document.querySelector(".flash-message")?.remove();
  }
});

ROOT.addEventListener("keydown", (event) => {
  const graphNode = event.target.closest?.("[data-graph-node]");
  if (!graphNode || !["Enter", " "].includes(event.key)) return;
  event.preventDefault();
  state.graphSelection = graphNode.dataset.graphNode;
  render();
});

render();
armMonitorScheduler();
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") armMonitorScheduler();
});
