"use strict";

const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
const byID = id => document.getElementById(id);
const make = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};

let state = null;
let selectedPlatform = "apple";
let pendingSecret = null;
let revealedToken = "";
let noticeTimer = 0;

async function request(path, body) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: JSON.stringify(body || {})
  });
  const text = await response.text();
  let value = {};
  try { value = text ? JSON.parse(text) : {}; } catch (_) {}
  if (!response.ok) throw new Error(value.error || "That request could not be completed.");
  return value;
}

function notify(message, good = false) {
  const notice = byID("notice");
  window.clearTimeout(noticeTimer);
  notice.textContent = message;
  notice.className = good ? "success" : "";
  noticeTimer = window.setTimeout(() => {
    notice.textContent = "";
    notice.className = "";
  }, 4500);
}

async function copyText(value, label = "Copied") {
  try {
    await navigator.clipboard.writeText(value);
    notify(label, true);
    return;
  } catch (_) {}
  const helper = make("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "");
  helper.style.position = "fixed";
  helper.style.opacity = "0";
  document.body.append(helper);
  helper.select();
  const copied = document.execCommand("copy");
  helper.remove();
  notify(copied ? label : "Copying was blocked by the browser.", copied);
}

async function mutate(path, body, message) {
  try {
    const value = await request(path, body);
    if (message) notify(message, true);
    await load();
    return value;
  } catch (error) {
    notify(error.message);
    throw error;
  }
}

async function load() {
  const response = await fetch("/api/state", {credentials: "same-origin"});
  if (response.status === 403) {
    location.href = "/login";
    return;
  }
  if (!response.ok) throw new Error("Could not load Torkitten.");
  state = await response.json();
  state.mappings ||= [];
  state.devices ||= [];
  state.tokens ||= [];
  state.components ||= [];
  render();
}

function route() {
  const requested = location.hash.slice(1);
  const active = ["dashboard", "applications", "devices", "runtime"].includes(requested) ? requested : "dashboard";
  document.querySelectorAll("[data-view]").forEach(view => view.hidden = view.dataset.view !== active);
  document.querySelectorAll("[data-tab]").forEach(tab => {
    if (tab.dataset.tab === active) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  if (location.hash !== `#${active}`) history.replaceState(null, "", `#${active}`);
  document.title = `${active[0].toUpperCase()}${active.slice(1)} · Torkitten`;
}

function componentDot(component) {
  const dot = make("i", "status-dot");
  if (component?.state === "running") dot.classList.add("good");
  else if (component?.state === "stopped") dot.classList.add("bad");
  return dot;
}

function render() {
  const allRunning = state.components.length === 3 && state.components.every(component => component.state === "running");
  const topDot = byID("top-status");
  topDot.className = `status-dot ${allRunning && state.publication_enabled ? "good" : allRunning ? "" : "bad"}`;
  byID("top-label").textContent = allRunning && state.publication_enabled ? "Running" : allRunning ? "Turned off" : "Needs attention";

  const mainURL = `https://${state.onion}/`;
  byID("onion").textContent = mainURL;
  const badge = byID("publication-badge");
  badge.textContent = state.publication_enabled ? "Running" : "Off";
  badge.className = `badge ${state.publication_enabled ? "good" : "bad"}`;
  byID("publication").textContent = state.publication_enabled ? "Turn off" : "Turn on";

  renderDashboardApplications();
  renderApplications();
  renderHealth();
  renderDevices();
  renderRuntime();
  renderAutomation();
}

function renderDashboardApplications() {
  const list = byID("dashboard-apps");
  list.replaceChildren();
  const enabled = state.mappings.filter(mapping => mapping.enabled);
  for (const mapping of enabled) {
    const item = make("div", "app-link");
    item.append(make("strong", "", mapping.prefix));
    list.append(item);
  }
  if (!enabled.length) list.append(make("div", "empty-state", "No applications yet."));
}

function renderApplications() {
  const list = byID("applications");
  list.replaceChildren();
  for (const mapping of state.mappings) {
    const url = `https://${mapping.prefix}.${state.onion}/`;
    const article = make("article", "application panel");
    const details = make("div");
    details.append(make("p", "kicker", "Private application"), make("h2", "", mapping.prefix));
    const block = make("div", "copy-block");
    block.append(make("code", "", url));
    const copy = make("button", "copy-button", "Copy");
    copy.type = "button";
    copy.addEventListener("click", () => copyText(url, "Application address copied"));
    block.append(copy);
    details.append(block);
    const figure = make("figure", "qr-tile");
    const image = make("img", "application-qr");
    image.src = `/api/application.png?prefix=${encodeURIComponent(mapping.prefix)}`;
    image.alt = `QR code for ${mapping.prefix}`;
    figure.append(image, make("figcaption", "", mapping.prefix));
    article.append(details, figure);
    list.append(article);
  }
  if (!state.mappings.length) list.append(make("div", "empty-state", "Add your first application above."));
}

function renderHealth() {
  const list = byID("dashboard-runtime");
  list.replaceChildren();
  for (const component of state.components) {
    const item = make("div", "health-item");
    const copy = make("div");
    copy.append(make("strong", "", component.name), make("small", "", component.state));
    item.append(componentDot(component), copy);
    list.append(item);
  }
}

function renderDevices() {
  const list = byID("devices");
  list.replaceChildren();
  for (const device of state.devices) {
    const row = make("div", "simple-row");
    const copy = make("div");
    copy.append(make("strong", "", device.name), make("small", "", `Connected ${new Date(device.acknowledged_at).toLocaleDateString()}`));
    row.append(copy, make("span", "badge good", "Authorized"));
    list.append(row);
  }
  if (!state.devices.length) list.append(make("div", "empty-state", "No remote devices connected."));
  if (state.pending_device && byID("device-dialog").open) renderPendingDevice();
}

function renderRuntime() {
  const list = byID("runtime-components");
  list.replaceChildren();
  for (const component of state.components) {
    const article = make("article", "runtime-component panel");
    const name = make("div", "runtime-name");
    const copy = make("div");
    copy.append(make("strong", "", component.name), make("small", "", component.last_error || component.state));
    name.append(componentDot(component), copy);
    const actions = make("div", "runtime-actions");
    const running = component.state === "running";
    const toggle = make("button", running ? "danger" : "secondary", running ? "Stop" : "Start");
    toggle.type = "button";
    toggle.dataset.component = component.name;
    toggle.dataset.action = running ? "stop" : "start";
    toggle.addEventListener("click", () => componentAction(component.name, running ? "stop" : "start"));
    const restart = make("button", "secondary", "Restart");
    restart.type = "button";
    restart.dataset.component = component.name;
    restart.dataset.action = "restart";
    restart.addEventListener("click", () => componentAction(component.name, "restart"));
    actions.append(toggle, restart);
    article.append(name, actions);
    list.append(article);
  }
}

function renderAutomation() {
  const enabled = state.tokens.length > 0;
  const toggle = byID("automation-toggle");
  toggle.checked = enabled;
  byID("automation-label").textContent = enabled ? "On" : "Off";
  const reveal = byID("token-once");
  reveal.hidden = !revealedToken;
  if (revealedToken) byID("token-value").textContent = revealedToken;
}

async function componentAction(name, action) {
  const confirmation = action === "start" ? "" : action.toUpperCase();
  try { await mutate("/api/components", {name, action, confirmation}, `${name} ${action} requested`); } catch (_) {}
}

function openDevice(platform) {
  selectedPlatform = platform;
  const titles = {apple: "iPhone or iPad", android: "Android", computer: "Computer"};
  const placeholders = {apple: "My iPhone", android: "My Android phone", computer: "My laptop"};
  byID("device-title").textContent = titles[platform];
  byID("device-form").elements.name.placeholder = placeholders[platform];
  const store = byID("store-step");
  store.hidden = platform === "computer";
  byID("device-form").querySelector(".step-number").textContent = platform === "computer" ? "1" : "2";
  if (!store.hidden) {
    const source = byID(platform === "apple" ? "apple-store-data" : "android-store-data");
    byID("store-link").href = source.dataset.link;
    byID("store-qr").src = source.dataset.qr;
    byID("store-copy").textContent = platform === "apple" ? "Scan this QR with the iPhone or iPad, then connect Orbot." : "Scan this QR with the Android device, then connect Orbot.";
  }
  byID("device-start").hidden = Boolean(state.pending_device);
  byID("pending-device").hidden = !state.pending_device;
  const dialog = byID("device-dialog");
  if (!dialog.open) dialog.showModal();
  if (state.pending_device) renderPendingDevice();
}

async function ensurePendingSecret() {
  const pending = state.pending_device;
  if (!pending) return null;
  if (pendingSecret?.id === pending.id && pendingSecret.credential) return pendingSecret;
  const response = await fetch("/api/devices/pending.auth_private", {credentials: "same-origin"});
  if (!response.ok) throw new Error("Could not load the private access credential.");
  const credential = (await response.text()).trim();
  const match = /^([a-z2-7]{56}):descriptor:x25519:([a-z2-7]{52})$/.exec(credential);
  if (!match) throw new Error("The private access credential was malformed.");
  pendingSecret = {id: pending.id, credential, address: `http://${match[1]}.onion`, key: match[2]};
  return pendingSecret;
}

async function renderPendingDevice() {
  const box = byID("pending-device");
  box.hidden = false;
  box.replaceChildren(make("p", "muted", "Loading private access…"));
  try {
    const secret = await ensurePendingSecret();
    if (!secret || !state.pending_device) return;
    box.replaceChildren();
    const access = make("section", "setup-step");
    access.append(make("span", "step-number", selectedPlatform === "computer" ? "1" : "3"));
    const content = make("div");
    content.append(make("h3", "", `Add private access to ${byID("device-title").textContent}`));
    if (selectedPlatform === "apple") {
      content.append(make("p", "", "In Orbot, open Client Authentication and scan this QR."));
      const qr = make("img", "setup-qr");
      qr.src = "/api/devices/pending.png";
      qr.alt = "QR code for Orbot client authorization";
      content.append(qr);
    } else {
      content.append(make("p", "", selectedPlatform === "android" ? "Download this authorization file, then import it from Orbot’s Client Authentication screen." : "Save this authorization file in the client-auth directory used by your Tor client."));
      const download = make("a", "button secondary", "Download .auth_private");
      download.href = "/api/devices/pending.auth_private";
      content.append(download);
    }
    const credential = make("div", "copy-block credential-block");
    credential.append(make("code", "", secret.credential));
    const copy = make("button", "copy-button", "Copy");
    copy.type = "button";
    copy.addEventListener("click", () => copyText(secret.credential, "Private access copied"));
    credential.append(copy);
    content.append(credential);
    access.append(content);

    const finish = make("section", "setup-step");
    finish.append(make("span", "step-number", selectedPlatform === "computer" ? "2" : "4"));
    const finishContent = make("div");
    finishContent.append(make("h3", "", "Open your private site"), make("p", "warning", "On the first visit, your browser may report the HTTPS certificate as untrusted. The onion connection is still encrypted and authenticated by Tor. Continue manually to reach the login; after signing in, certificate installation is optional."));
    const mainURL = `https://${state.onion}/`;
    const finalBlock = make("div", "copy-block");
    finalBlock.append(make("code", "", mainURL));
    const finalCopy = make("button", "copy-button", "Copy");
    finalCopy.type = "button";
    finalCopy.addEventListener("click", () => copyText(mainURL, "Site address copied"));
    finalBlock.append(finalCopy);
    const finalQR = byID("main-qr").cloneNode();
    finalQR.removeAttribute("id");
    finalQR.className = "setup-qr";
    finishContent.append(finalBlock, finalQR);
    const acknowledge = make("button", "", "Finish and erase setup key");
    acknowledge.type = "button";
    acknowledge.addEventListener("click", async () => {
      try {
        await mutate("/api/devices/acknowledge", {id: state.pending_device.id}, "Device connected");
        pendingSecret = null;
        byID("device-dialog").close();
      } catch (_) {}
    });
    finishContent.append(acknowledge);
    finish.append(finishContent);
    box.append(access, finish);
  } catch (error) {
    box.replaceChildren(make("p", "alert", error.message));
  }
}

function agentPrompt(token) {
  return `Use the local Torkitten Applications API at http://localhost:12755.\n\nAuthenticate every request with this HTTP header:\nAuthorization: Bearer ${token}\n\nAllowed operations:\n- GET /api/mappings\n- POST /api/mappings/create with {"prefix":"name","port":7777,"protocol":"http"}\n- POST /api/mappings/update\n- POST /api/mappings/enable\n- POST /api/mappings/test\n- POST /api/mappings/delete\n\nExample CLI request:\ncurl -H 'Authorization: Bearer ${token}' http://localhost:12755/api/mappings\n\nThe token grants application-mapping authority. Do not print it, log it, or send it to another host.`;
}

byID("mapping-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = new FormData(form);
  try {
    await mutate("/api/mappings/create", {prefix: values.get("prefix"), port: Number(values.get("port")), protocol: "http"}, "Application added");
    form.reset();
  } catch (_) {}
});

byID("publication").addEventListener("click", async () => {
  if (!state.publication_enabled && !state.devices.length) {
    notify("Connect a remote device before turning Torkitten on.");
    location.hash = "#devices";
    return;
  }
  const enabled = !state.publication_enabled;
  try { await mutate("/api/publication", {enabled, confirmation: enabled ? "START" : "STOP"}, enabled ? "Torkitten turned on" : "Torkitten turned off"); } catch (_) {}
});

byID("device-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const name = new FormData(form).get("name");
  try {
    const value = await request("/api/devices/create", {name});
    pendingSecret = {id: value.id, credential: value.credential};
    form.reset();
    await load();
    byID("device-start").hidden = true;
    await renderPendingDevice();
  } catch (error) { notify(error.message); }
});

document.querySelectorAll("[data-platform]").forEach(button => button.addEventListener("click", () => openDevice(button.dataset.platform)));
byID("automation-toggle").addEventListener("change", async event => {
  const toggle = event.currentTarget;
  toggle.disabled = true;
  try {
    if (toggle.checked && !state.tokens.length) {
      const value = await request("/api/tokens/create", {name: "CLI and agent access", scopes: [], lifetime_hours: 0});
      revealedToken = value.token;
      notify("CLI and agent access enabled", true);
      await load();
    } else if (!toggle.checked) {
      for (const token of state.tokens) await request("/api/tokens/revoke", {id: token.id, confirmation: "REVOKE"});
      revealedToken = "";
      notify("CLI and agent access disabled", true);
      await load();
    }
  } catch (error) {
    notify(error.message);
    await load().catch(() => {});
  } finally { toggle.disabled = false; }
});

document.addEventListener("click", event => {
  const copy = event.target.closest("[data-copy]")?.dataset.copy;
  if (copy) copyText(byID(copy).textContent);
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "logout") request("/logout", {}).finally(() => location.href = "/login").catch(() => {});
  if (action === "close-device") byID("device-dialog").close();
  if (action === "copy-agent-prompt" && revealedToken) copyText(agentPrompt(revealedToken), "Agent prompt copied");
});

byID("device-dialog").addEventListener("click", event => {
  if (event.target === byID("device-dialog")) byID("device-dialog").close();
});
window.addEventListener("hashchange", route);
route();
load().catch(error => notify(error.message));
window.setInterval(() => load().catch(() => {}), 5000);
