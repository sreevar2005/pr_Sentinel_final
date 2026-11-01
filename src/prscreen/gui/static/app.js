// prscreen GUI. Everything taken from a pull request is inserted with textContent, never as
// HTML, so a crafted diff cannot add markup or scripts to this page.
"use strict";

const TOKEN_KEY = "prscreen-token";
const SEVERITIES = ["high", "medium", "low"];
const state = { mode: "diff", rules: new Map(), lastMarkdown: "", hidden: new Set(), findings: [] };

function readToken() {
  const params = new URLSearchParams(location.search);
  const fromUrl = params.get("token");
  if (fromUrl) {
    try { sessionStorage.setItem(TOKEN_KEY, fromUrl); } catch (e) { /* private mode */ }
    history.replaceState(null, "", location.pathname); // keep the token out of the address bar
    return fromUrl;
  }
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; }
}
const token = readToken();

async function api(path, body) {
  const response = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "X-Prscreen-Token": token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({ error: "The server sent an unreadable reply." }));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

const $ = (id) => document.getElementById(id);

// --- tabs and input mode -------------------------------------------------------------------

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => {
      const active = t === tab;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", String(active));
      $(`tab-${t.dataset.tab}`).hidden = !active;
    });
  });
});

document.querySelectorAll(".seg").forEach((seg) => {
  seg.addEventListener("click", () => {
    state.mode = seg.dataset.mode;
    document.querySelectorAll(".seg").forEach((s) => {
      s.classList.toggle("active", s === seg);
      s.setAttribute("aria-checked", String(s === seg));
    });
    $("mode-diff").hidden = state.mode !== "diff";
    $("mode-git").hidden = state.mode !== "git";
  });
});

// --- scanning ------------------------------------------------------------------------------

async function runScan() {
  const button = $("scan");
  $("error").hidden = true;
  const request = { mode: state.mode, min_severity: $("min-severity").value };
  if (state.mode === "diff") request.diff = $("diff").value;
  else Object.assign(request, { repo: $("repo").value.trim(), range: $("range").value.trim() });
  button.disabled = true;
  button.textContent = "Scanning…";
  try {
    const data = await api("/api/scan", request);
    state.lastMarkdown = data.markdown;
    showResults(data.result);
  } catch (error) {
    $("results").hidden = true;
    $("error").textContent = error.message;
    $("error").hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Scan";
  }
}

function showResults(result) {
  state.findings = result.findings;
  state.hidden.clear();
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  result.findings.forEach((f) => { counts[f.severity] += 1; });

  const verdict = $("verdict");
  const files = result.files_scanned === 1 ? "1 file" : `${result.files_scanned} files`;
  if (result.findings.length === 0) {
    verdict.textContent = `✓ Nothing risky found in ${files}`;
    verdict.className = "verdict clean";
  } else {
    const noun = result.findings.length === 1 ? "finding" : "findings";
    verdict.textContent = `${result.findings.length} ${noun} in ${files}`;
    verdict.className = "verdict";
  }

  const chips = $("chips");
  chips.replaceChildren();
  SEVERITIES.forEach((severity) => {
    if (!counts[severity]) return;
    const chip = el("button", "chip");
    chip.append(el("span", "n", counts[severity]), el("span", `sev ${severity}`, severity));
    chip.title = "Show or hide";
    chip.addEventListener("click", () => {
      if (state.hidden.has(severity)) state.hidden.delete(severity); else state.hidden.add(severity);
      chip.classList.toggle("off", state.hidden.has(severity));
      renderFindings();
    });
    chips.append(chip);
  });
  $("copy-md").hidden = result.findings.length === 0;

  const notes = $("notes");
  notes.replaceChildren();
  result.skipped.forEach((s) => notes.append(el("div", "", `Skipped ${s.path}: ${s.reason}`)));
  result.capped.forEach((c) => notes.append(el("div", "", `${c.rule_id} in ${c.path}: ${c.dropped} more not shown`)));
  result.errors.forEach((e) => notes.append(el("div", "", `⚠ ${e} (results are incomplete)`)));

  renderFindings();
  $("results").hidden = false;
}

function renderFindings() {
  const list = $("findings");
  list.replaceChildren();
  if (state.findings.length === 0) {
    const card = el("li", "clean-card");
    card.append(el("strong", "", "No findings."), el("div", "muted",
      "prscreen found no risky patterns in these changes. That is not a guarantee: still review the code."));
    list.append(card);
    return;
  }
  state.findings
    .filter((f) => !state.hidden.has(f.severity))
    .forEach((f) => list.append(findingCard(f)));
}

function findingCard(f) {
  const rule = state.rules.get(f.rule_id) || {};
  const card = el("li", `finding ${f.severity}`);
  const head = el("div", "finding-head");
  head.append(
    el("span", `sev ${f.severity}`, f.severity),
    el("span", "rule-id", f.rule_id),
    el("span", "title", f.title),
    el("span", "location", f.line ? `${f.path}:${f.line}` : f.path),
  );
  card.append(head, el("pre", "evidence", f.evidence));
  if (f.detail) card.append(el("p", "detail", f.detail));
  if (rule.rationale) card.append(collapsible("Why it matters", rule.rationale));
  if (rule.benign) card.append(collapsible("Could be harmless if", rule.benign));
  if (f.ai_note) card.append(el("p", "ai-note", `AI note (unverified): ${f.ai_note}`));
  card.append(el("div", "muted", `Confidence: ${f.confidence}`));
  return card;
}

function collapsible(label, text) {
  const details = el("details");
  details.append(el("summary", "", label), el("p", "", text));
  return details;
}

$("scan").addEventListener("click", runScan);
$("diff").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) runScan();
});
$("copy-md").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.lastMarkdown);
    $("copy-md").textContent = "Copied ✓";
  } catch (e) {
    $("copy-md").textContent = "Copy failed";
  }
  setTimeout(() => { $("copy-md").textContent = "Copy Markdown report"; }, 1500);
});

// --- git repository mode -------------------------------------------------------------------

async function loadBranches() {
  const button = $("load-branches");
  $("error").hidden = true;
  button.disabled = true;
  button.textContent = "Loading…";
  try {
    const { branches, base } = await api("/api/branches", { repo: $("repo").value.trim() });
    const compare = $("compare-branch");
    const baseSelect = $("base-branch");
    compare.replaceChildren();
    baseSelect.replaceChildren();
    branches.forEach((name) => {
      baseSelect.append(new Option(name, name, false, name === base));
      if (name !== base) compare.append(new Option(name, name));
    });
    $("branch-pickers").hidden = false;
    updateRange();
  } catch (error) {
    $("branch-pickers").hidden = true;
    $("error").textContent = error.message;
    $("error").hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Load branches";
  }
}

function updateRange() {
  const base = $("base-branch").value;
  const compare = $("compare-branch").value;
  if (base && compare) $("range").value = `${base}...${compare}`;
}

$("load-branches").addEventListener("click", loadBranches);
$("repo").addEventListener("keydown", (event) => { if (event.key === "Enter") loadBranches(); });
$("compare-branch").addEventListener("change", () => { updateRange(); runScan(); });
$("base-branch").addEventListener("change", updateRange);

// --- examples and rules --------------------------------------------------------------------

async function loadSamples() {
  const { samples } = await api("/api/samples");
  const select = $("sample");
  samples.forEach((sample, index) =>
    select.append(new Option(sample.year ? `${sample.year} · ${sample.title}` : sample.title, String(index))));
  select.addEventListener("change", () => {
    if (select.value === "") return;
    const sample = samples[Number(select.value)];
    document.querySelector('.seg[data-mode="diff"]').click();
    $("diff").value = sample.diff;
    select.value = "";
    showIncident(sample);
    runScan();
  });
  // Editing the input or switching mode means the incident card no longer describes it.
  $("diff").addEventListener("input", () => showIncident(null));
  document.querySelectorAll(".seg").forEach((seg) => seg.addEventListener("click", () => {
    if (seg.dataset.mode === "git") showIncident(null);
  }));
}

function showIncident(sample) {
  $("incident").hidden = !sample;
  if (!sample) return;
  $("incident-year").textContent = sample.year || "";
  $("incident-title").textContent = sample.title;
  const sources = Array.isArray(sample.sources) ? sample.sources : [];
  // An older prscreen server sends examples without these fields: say so instead of "undefined".
  const stale = !sample.recreation || sources.length === 0;
  $("incident-recreation").textContent = stale
    ? "This prscreen window is older than the page. Close it and start prscreen gui again to see the incident details and sources."
    : `In this example: ${sample.recreation}`;
  $("incident-summary").textContent = sample.summary || "";
  $("incident-year").hidden = !sample.year;
  $("incident-sources").parentElement.hidden = sources.length === 0;
  const links = $("incident-sources");
  links.replaceChildren();
  sources.forEach((source) => {
    if (!source || typeof source.url !== "string" || !/^https:\/\//.test(source.url)) return; // https only
    const link = el("a", "", source.name);
    link.href = source.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    links.append(link);
  });
}

async function loadRules() {
  const { version, rules } = await api("/api/rules");
  $("version").textContent = `prscreen ${version}`;
  rules.forEach((rule) => state.rules.set(rule.id, rule));
  renderRules("");
  $("rule-search").addEventListener("input", (event) => renderRules(event.target.value.trim().toLowerCase()));
}

function renderRules(query) {
  const container = $("rules");
  container.replaceChildren();
  const matches = [...state.rules.values()].filter((r) =>
    !query || [r.id, r.title, r.category, r.rationale].join(" ").toLowerCase().includes(query));
  $("rule-count").textContent = `${matches.length} of ${state.rules.size} rules`;
  const byCategory = new Map();
  matches.forEach((r) => byCategory.set(r.category, [...(byCategory.get(r.category) || []), r]));
  byCategory.forEach((rules, category) => {
    const group = el("div", "rule-group");
    group.append(el("h2", "", category.replace("-", " ")));
    rules.forEach((r) => {
      const item = el("details", "rule");
      const summary = el("summary");
      summary.append(el("span", `sev ${r.severity}`, r.severity), el("span", "rule-id", r.id), el("span", "title", r.title));
      item.append(summary, el("p", "", r.rationale), el("p", "muted", `Could be harmless if: ${r.benign}`));
      group.append(item);
    });
    container.append(group);
  });
}

if (!token) {
  $("token-warning").hidden = false;
  $("scan").disabled = true;
} else {
  Promise.all([loadRules(), loadSamples()]).catch((error) => {
    $("error").textContent = error.message;
    $("error").hidden = false;
  });
}
