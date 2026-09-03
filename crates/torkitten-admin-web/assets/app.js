"use strict";

const notice = document.querySelector("#notice");
let noticeTimer;

function csrfToken() {
  const item = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("torkitten_admin_csrf="));
  return item ? item.slice(item.indexOf("=") + 1) : "";
}

async function api(path, body = {}) {
  const headers = { "Content-Type": "application/json" };
  const csrf = csrfToken();
  if (csrf) headers["X-Torkitten-CSRF"] = csrf;
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers,
    body: JSON.stringify(body),
  });
  let payload;
  try {
    payload = await response.json();
  } catch (_) {
    payload = { error: `Request failed (${response.status})` };
  }
  if (!response.ok || payload.result === "error") {
    throw new Error(payload.error || payload.message || `Request failed (${response.status})`);
  }
  return payload;
}

function showNotice(message, kind = "success") {
  if (!notice) return;
  window.clearTimeout(noticeTimer);
  notice.textContent = message;
  notice.className = `notice ${kind}`;
  notice.hidden = false;
  noticeTimer = window.setTimeout(() => { notice.hidden = true; }, 7000);
}

async function pending(button, label, operation, reload = true) {
  const original = button.innerHTML;
  button.setAttribute("aria-busy", "true");
  button.disabled = true;
  button.textContent = label;
  try {
    await operation();
    showNotice("Change committed by the Torkitten daemon.");
    if (reload) {
      window.setTimeout(() => window.location.reload(), 350);
    } else {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.innerHTML = original;
    }
    return true;
  } catch (error) {
    showNotice(error.message, "error");
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.innerHTML = original;
    return false;
  }
}

for (const form of document.querySelectorAll("#setup-form, #login-form")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    if (form.id === "setup-form" && data.get("password") !== data.get("confirmation")) {
      showNotice("The password confirmation does not match.", "error");
      return;
    }
    const button = form.querySelector("button[type=submit]");
    const authenticated = await pending(
      button,
      form.id === "setup-form" ? "Creating…" : "Signing in…",
      () => api(form.dataset.endpoint, {
        username: data.get("username"),
        password: data.get("password"),
      }),
      false,
    );
    if (authenticated) window.location.replace("/");
  });
}

const remotePolicyForm = document.querySelector("#remote-policy-form");
if (remotePolicyForm) remotePolicyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(remotePolicyForm);
  const passkeysEnabled = data.has("passkeys_enabled");
  const passwordTotpEnabled = data.has("password_totp_enabled");
  if (!passkeysEnabled && !passwordTotpEnabled) {
    showNotice("Keep passkeys or password plus TOTP enabled.", "error");
    return;
  }
  const button = remotePolicyForm.querySelector("button[type=submit]");
  await pending(button, "Saving…", () => api("/api/settings/remote-access", {
    passkeys_enabled: passkeysEnabled,
    password_totp_enabled: passwordTotpEnabled,
    session_days: Number(data.get("session_days")),
  }));
});

const administratorCredentialsForm = document.querySelector("#administrator-credentials-form");
if (administratorCredentialsForm) administratorCredentialsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(administratorCredentialsForm);
  if (data.get("password") !== data.get("confirmation")) {
    showNotice("The password confirmation does not match.", "error");
    return;
  }
  if (!window.confirm("Change the local administrator and sign out every administration session?")) return;
  const button = administratorCredentialsForm.querySelector("button[type=submit]");
  const changed = await pending(button, "Changing…", () => api("/api/settings/administrator", {
    username: data.get("username"),
    password: data.get("password"),
  }), false);
  if (changed) window.location.replace("/");
});

const generatorDialog = document.querySelector("#generator-dialog");
const candidateAddress = document.querySelector("#candidate-address");
const candidateCount = document.querySelector("#candidate-count");
const candidateSpinner = document.querySelector("#candidate-spinner");
const generatorStart = document.querySelector("#generator-start");
const generatorStop = document.querySelector("#generator-stop");
const createSiteForm = document.querySelector("#create-site-form");
let generating = false;
let selectedCandidate = null;
let generatedCount = 0;

function stopGenerator() {
  generating = false;
  if (candidateSpinner) candidateSpinner.classList.remove("running");
  if (generatorStart) generatorStart.disabled = false;
  if (generatorStop) generatorStop.disabled = true;
  if (createSiteForm) createSiteForm.hidden = !selectedCandidate;
}

async function generatorLoop() {
  while (generating) {
    try {
      const result = await api("/api/generator/candidate");
      if (!generating) break;
      selectedCandidate = result;
      generatedCount += 1;
      candidateAddress.textContent = result.onion_hostname;
      candidateCount.textContent = `${generatedCount} candidate${generatedCount === 1 ? "" : "s"}`;
      await new Promise((resolve) => window.setTimeout(resolve, 35));
    } catch (error) {
      stopGenerator();
      showNotice(error.message, "error");
      break;
    }
  }
}

if (generatorStart) generatorStart.addEventListener("click", () => {
  selectedCandidate = null;
  generatedCount = 0;
  createSiteForm.hidden = true;
  generating = true;
  generatorStart.disabled = true;
  generatorStop.disabled = false;
  candidateSpinner.classList.add("running");
  candidateAddress.textContent = "Generating…";
  candidateCount.textContent = "0 candidates";
  void generatorLoop();
});

if (generatorStop) generatorStop.addEventListener("click", stopGenerator);
if (generatorDialog) generatorDialog.addEventListener("close", stopGenerator);

if (createSiteForm) createSiteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedCandidate) {
    showNotice("Generate and stop on a candidate first.", "error");
    return;
  }
  const data = new FormData(createSiteForm);
  const button = createSiteForm.querySelector("button[type=submit]");
  await pending(button, "Creating…", () => api("/api/sites", {
    id: data.get("id"),
    display_name: data.get("display_name"),
    candidate_id: selectedCandidate.candidate_id,
  }));
});

const mappingDialog = document.querySelector("#mapping-dialog");
const mappingForm = document.querySelector("#mapping-form");
const deviceDialog = document.querySelector("#device-dialog");
const deviceForm = document.querySelector("#device-form");
const deviceResult = document.querySelector("#device-result");
let wizardSiteId = null;
let wizardEnrollment = null;
let bootstrapExpiresUnix = null;
let bootstrapTimer = null;

async function loadQr(image, value) {
  image.removeAttribute("src");
  image.setAttribute("aria-busy", "true");
  try {
    const result = await api("/api/qr", { value });
    image.src = result.image;
  } catch (_) {
    image.alt = `${image.alt} (QR generation failed; use the copy control)`;
  } finally {
    image.removeAttribute("aria-busy");
  }
}

function linkedValue(linkId, codeId, value) {
  document.querySelector(`#${linkId}`).href = value;
  document.querySelector(`#${codeId}`).textContent = value;
}

function selectPlatform(platform) {
  for (const button of document.querySelectorAll("[data-platform]")) {
    const selected = button.dataset.platform === platform;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", selected ? "true" : "false");
    button.tabIndex = selected ? 0 : -1;
  }
  for (const panel of document.querySelectorAll("[data-platform-panel], [data-platform-auth], [data-platform-cert]")) {
    const candidate = panel.dataset.platformPanel || panel.dataset.platformAuth || panel.dataset.platformCert;
    panel.hidden = candidate !== platform;
  }
  for (const field of document.querySelectorAll(".desktop-auth-field")) {
    field.hidden = platform === "ios" || platform === "android";
  }
  const panel = document.querySelector(`[data-platform-panel="${platform}"]`);
  const staticQr = panel?.querySelector("[data-static-qr]");
  if (staticQr && !staticQr.hasAttribute("src")) void loadQr(staticQr, staticQr.dataset.staticQr);
}

function stopBootstrapTimer() {
  if (bootstrapTimer) window.clearInterval(bootstrapTimer);
  bootstrapTimer = null;
}

function updateBootstrapCountdown() {
  const countdown = document.querySelector("#bootstrap-countdown");
  if (!bootstrapExpiresUnix) {
    countdown.textContent = "Not open";
    return;
  }
  const remaining = Math.max(0, bootstrapExpiresUnix - Math.floor(Date.now() / 1000));
  const minutes = Math.floor(remaining / 60);
  const seconds = String(remaining % 60).padStart(2, "0");
  countdown.textContent = remaining ? `${minutes}:${seconds} remaining` : "Window expired";
  if (!remaining) {
    stopBootstrapTimer();
    document.querySelector("[data-action=wizard-bootstrap-close]").hidden = true;
    document.querySelector("[data-action=wizard-bootstrap-extend]").hidden = false;
  }
}

function showBootstrap(result) {
  bootstrapExpiresUnix = result.expires_unix;
  linkedValue("bootstrap-link", "bootstrap-url", result.url);
  document.querySelector("#bootstrap-result").hidden = false;
  document.querySelector("[data-action=wizard-bootstrap-open]").hidden = true;
  document.querySelector("[data-action=wizard-bootstrap-extend]").hidden = false;
  document.querySelector("[data-action=wizard-bootstrap-close]").hidden = false;
  void loadQr(document.querySelector("#bootstrap-qr"), result.url);
  stopBootstrapTimer();
  updateBootstrapCountdown();
  bootstrapTimer = window.setInterval(updateBootstrapCountdown, 1000);
}

function clearDeviceResult() {
  wizardEnrollment = null;
  deviceResult.hidden = true;
  deviceForm.hidden = false;
  for (const section of document.querySelectorAll("[data-enrollment-only]")) section.hidden = true;
  for (const id of ["device-onion", "device-credential", "device-private-key", "device-enrollment-url", "device-main-url"]) {
    document.querySelector(`#${id}`).textContent = "";
  }
  for (const id of ["device-onion-qr", "device-credential-qr", "device-enrollment-qr", "device-main-qr"]) {
    document.querySelector(`#${id}`).removeAttribute("src");
  }
  document.querySelector("#device-enrollment-link").removeAttribute("href");
  document.querySelector("#device-main-link").removeAttribute("href");
}

function showDeviceResult(result) {
  wizardEnrollment = result;
  const mainUrl = `https://${result.onion_hostname}/`;
  const privateKey = result.credential.split(":").at(-1);
  document.querySelector("#device-onion").textContent = result.onion_hostname;
  document.querySelector("#device-credential").textContent = result.credential;
  document.querySelector("#device-private-key").textContent = privateKey;
  linkedValue("device-enrollment-link", "device-enrollment-url", result.enrollment_url);
  linkedValue("device-main-link", "device-main-url", mainUrl);
  deviceForm.hidden = true;
  deviceResult.hidden = false;
  for (const section of document.querySelectorAll("[data-enrollment-only]")) section.hidden = false;
  const platform = document.querySelector("[data-platform][aria-selected=true]")?.dataset.platform || "ios";
  selectPlatform(platform);
  void loadQr(document.querySelector("#device-onion-qr"), mainUrl);
  void loadQr(document.querySelector("#device-credential-qr"), result.credential);
  void loadQr(document.querySelector("#device-enrollment-qr"), result.enrollment_url);
  void loadQr(document.querySelector("#device-main-qr"), mainUrl);
}

function mappingPayload(form) {
  const data = new FormData(form);
  return {
    id: data.get("id"),
    display_name: data.get("display_name"),
    virtual_port: Number(data.get("virtual_port")),
    target_kind: data.get("target_kind"),
    address: data.get("address") || null,
    port: data.get("port") ? Number(data.get("port")) : null,
    path: data.get("path") || null,
    transport: data.get("transport"),
    enabled: data.get("enabled") === "true",
  };
}

function updateTargetFields() {
  if (!mappingForm) return;
  const kind = mappingForm.elements.target_kind.value;
  for (const group of mappingForm.querySelectorAll("[data-target]")) group.hidden = group.dataset.target !== kind;
}

if (mappingForm) {
  mappingForm.elements.target_kind.addEventListener("change", updateTargetFields);
  mappingForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const siteId = mappingForm.elements.site_id.value;
    const button = mappingForm.querySelector("button[type=submit]");
    await pending(button, "Saving…", () => api(`/api/sites/${encodeURIComponent(siteId)}/mappings`, mappingPayload(mappingForm)));
  });
}

document.querySelector("[data-action=test-mapping-form]")?.addEventListener("click", async (event) => {
  const siteId = mappingForm.elements.site_id.value;
  await pending(event.currentTarget, "Testing…", async () => {
    const result = await api(`/api/sites/${encodeURIComponent(siteId)}/mappings/test`, mappingPayload(mappingForm));
    if (!result.reachable) throw new Error("The local target is not reachable.");
    showNotice("The local target is reachable.");
  }, false);
});

function prepareDeviceWizard(siteCard) {
  wizardSiteId = siteCard.dataset.siteId;
  deviceForm.reset();
  deviceForm.elements.site_id.value = wizardSiteId;
  clearDeviceResult();
  bootstrapExpiresUnix = null;
  stopBootstrapTimer();
  document.querySelector("#bootstrap-result").hidden = true;
  document.querySelector("#bootstrap-url").textContent = "";
  document.querySelector("#bootstrap-qr").removeAttribute("src");
  document.querySelector("[data-action=wizard-bootstrap-open]").hidden = false;
  document.querySelector("[data-action=wizard-bootstrap-extend]").hidden = true;
  document.querySelector("[data-action=wizard-bootstrap-close]").hidden = true;
  updateBootstrapCountdown();
  selectPlatform("ios");
  const guests = document.querySelector("#existing-guests");
  guests.replaceChildren();
  for (const guest of siteCard.querySelectorAll("[data-guest-id]")) {
    const option = document.createElement("option");
    option.value = guest.dataset.guestId;
    option.label = guest.dataset.guestName;
    option.dataset.guestName = guest.dataset.guestName;
    guests.append(option);
  }
  const grants = document.querySelector("#device-mapping-grants");
  grants.replaceChildren();
  for (const mapping of siteCard.querySelectorAll("[data-mapping-id]")) {
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "mapping_ids";
    checkbox.value = mapping.dataset.mappingId;
    checkbox.checked = mapping.dataset.enabled === "true";
    label.append(checkbox, document.createTextNode(mapping.querySelector(".mapping-main strong").textContent));
    grants.append(label);
  }
}

if (deviceForm) {
  deviceForm.elements.guest_id.addEventListener("change", () => {
    const selected = [...document.querySelector("#existing-guests").options]
      .find((option) => option.value === deviceForm.elements.guest_id.value);
    if (selected) deviceForm.elements.guest_name.value = selected.dataset.guestName;
  });
  deviceForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(deviceForm);
    const button = deviceForm.querySelector("button[type=submit]");
    await pending(button, "Creating…", async () => {
      const result = await api(`/api/sites/${encodeURIComponent(wizardSiteId)}/devices/enroll`, {
        guest_id: data.get("guest_id"),
        guest_name: data.get("guest_name"),
        device_id: data.get("device_id"),
        device_name: data.get("device_name"),
        client_name: data.get("client_name"),
        mapping_ids: data.getAll("mapping_ids"),
      });
      showDeviceResult(result);
      showNotice("Device authorization created and publication updated.");
    }, false);
  });
  deviceDialog.addEventListener("close", () => {
    wizardSiteId = null;
    deviceForm.reset();
    clearDeviceResult();
    bootstrapExpiresUnix = null;
    stopBootstrapTimer();
    document.querySelector("#bootstrap-url").textContent = "";
    document.querySelector("#bootstrap-qr").removeAttribute("src");
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  if (button.dataset.copy) {
    event.preventDefault();
    try { await navigator.clipboard.writeText(button.dataset.copy); showNotice("Copied to clipboard."); }
    catch (_) { showNotice("Clipboard access was denied.", "error"); }
    return;
  }
  if (button.dataset.copyTarget) {
    const value = document.querySelector(`#${button.dataset.copyTarget}`)?.textContent || "";
    try { await navigator.clipboard.writeText(value); showNotice("Copied to clipboard."); }
    catch (_) { showNotice("Clipboard access was denied.", "error"); }
    return;
  }
  if (button.dataset.copyResult) {
    const selector = button.dataset.copyResult === "onion" ? "#device-onion" : "#device-credential";
    try { await navigator.clipboard.writeText(document.querySelector(selector).textContent); showNotice("Copied to clipboard."); }
    catch (_) { showNotice("Clipboard access was denied.", "error"); }
    return;
  }
  const action = button.dataset.action;
  if (!action) return;
  const siteCard = button.closest("[data-site-id]");
  const siteId = siteCard?.dataset.siteId;
  const mappingRow = button.closest("[data-mapping-id]");
  const mappingId = mappingRow?.dataset.mappingId;

  if (action === "refresh") { window.location.reload(); return; }
  if (action === "open-generator") { generatorDialog.showModal(); return; }
  if (action === "open-mapping") {
    mappingForm.reset();
    mappingForm.elements.site_id.value = siteId;
    mappingForm.elements.enabled.value = "true";
    updateTargetFields();
    mappingDialog.showModal();
    return;
  }
  if (action === "connect-device") { prepareDeviceWizard(siteCard); deviceDialog.showModal(); return; }
  if (action === "target-kind") { updateTargetFields(); return; }
  if (action === "logout") { await pending(button, "Signing out…", () => api("/api/logout")); return; }
  if (action === "toggle-site") {
    const enabled = button.dataset.enabled === "true";
    await pending(button, "…", () => api(`/api/sites/${encodeURIComponent(siteId)}/enabled`, { enabled: !enabled }));
    return;
  }
  if (action === "rename-site") {
    const displayName = window.prompt("New site name:");
    if (displayName) await pending(button, "Renaming…", () => api(`/api/sites/${encodeURIComponent(siteId)}/rename`, { display_name: displayName }));
    return;
  }
  if (["stop-site", "restart-site", "rotate-site"].includes(action)) {
    const verb = action.replace("-site", "");
    if (verb === "rotate" && !window.confirm("Rotate this persistent onion identity? The old address will stop working.")) return;
    await pending(button, `${verb[0].toUpperCase()}${verb.slice(1)}ing…`, () => api(`/api/sites/${encodeURIComponent(siteId)}/${verb}`));
    return;
  }
  if (action === "remove-site") {
    if (!window.confirm("Remove this onion site, its mappings, identity, and certificate?")) return;
    await pending(button, "Removing…", () => api(`/api/sites/${encodeURIComponent(siteId)}/remove`));
    return;
  }
  if (action === "open-bootstrap" || action === "close-bootstrap") {
    const verb = action.startsWith("open") ? "open" : "close";
    await pending(button, verb === "open" ? "Opening…" : "Closing…", async () => {
      const result = await api(`/api/sites/${encodeURIComponent(siteId)}/bootstrap/${verb}`, verb === "open" ? { seconds: 900 } : {});
      if (result.url) showNotice(`Certificate download opened: ${result.url}`);
    });
    return;
  }
  if (action === "toggle-mapping") {
    const enabled = button.dataset.enabled === "true";
    await pending(button, "…", () => api(`/api/sites/${encodeURIComponent(siteId)}/mappings/${encodeURIComponent(mappingId)}/enabled`, { enabled: !enabled }));
    return;
  }
  if (action === "remove-mapping") {
    if (!window.confirm("Remove this application mapping?")) return;
    await pending(button, "Removing…", () => api(`/api/sites/${encodeURIComponent(siteId)}/mappings/${encodeURIComponent(mappingId)}/remove`));
    return;
  }
  if (action === "revoke-device") {
    const guestId = button.closest("[data-guest-id]").dataset.guestId;
    const deviceId = button.closest("[data-device-id]").dataset.deviceId;
    if (!window.confirm("Revoke this device’s Tor authorization?")) return;
    await pending(button, "…", () => api(`/api/sites/${encodeURIComponent(siteId)}/guests/${encodeURIComponent(guestId)}/devices/${encodeURIComponent(deviceId)}/revoke`));
    return;
  }
  if (action === "remove-guest") {
    const guestId = button.closest("[data-guest-id]").dataset.guestId;
    if (!window.confirm("Remove this guest?")) return;
    await pending(button, "Removing…", () => api(`/api/sites/${encodeURIComponent(siteId)}/guests/${encodeURIComponent(guestId)}/remove`));
    return;
  }
  if (action === "reset-guest-login") {
    const guestId = button.closest("[data-guest-id]").dataset.guestId;
    if (!window.confirm("Reset this guest’s login? Existing passkeys, password, TOTP, sessions, recovery data, and pending enrollment links will stop working. Tor device keys and mapping grants remain.")) return;
    await pending(button, "Resetting…", () => api(`/api/sites/${encodeURIComponent(siteId)}/guests/${encodeURIComponent(guestId)}/reset-login`));
    return;
  }
  if (action === "edit-mapping") {
    mappingForm.reset();
    mappingForm.elements.site_id.value = siteId;
    mappingForm.elements.id.value = mappingId;
    mappingForm.elements.display_name.value = mappingRow.dataset.displayName;
    mappingForm.elements.virtual_port.value = mappingRow.dataset.virtualPort;
    mappingForm.elements.target_kind.value = mappingRow.dataset.targetKind;
    mappingForm.elements.address.value = mappingRow.dataset.address;
    mappingForm.elements.port.value = mappingRow.dataset.port === "0" ? "" : mappingRow.dataset.port;
    mappingForm.elements.path.value = mappingRow.dataset.path;
    mappingForm.elements.transport.value = mappingRow.dataset.transport;
    mappingForm.elements.enabled.value = mappingRow.dataset.enabled;
    updateTargetFields();
    mappingDialog.showModal();
    return;
  }
  if (action === "test-mapping") {
    const payload = {
      id: mappingId,
      display_name: mappingRow.dataset.displayName,
      virtual_port: Number(mappingRow.dataset.virtualPort),
      target_kind: mappingRow.dataset.targetKind,
      address: mappingRow.dataset.address || null,
      port: Number(mappingRow.dataset.port) || null,
      path: mappingRow.dataset.path || null,
      transport: mappingRow.dataset.transport,
      enabled: mappingRow.dataset.enabled === "true",
    };
    await pending(button, "Testing…", async () => {
      const result = await api(`/api/sites/${encodeURIComponent(siteId)}/mappings/test`, payload);
      if (!result.reachable) throw new Error("The local target is not reachable.");
      showNotice("The local target is reachable.");
    }, false);
    return;
  }
  if (action === "resume") {
    const enabled = button.dataset.enabled === "true";
    await pending(button, "Saving…", () => api("/api/settings/resume", { enabled: !enabled }));
    return;
  }
  if (action === "emergency-stop") {
    if (!window.confirm("Stop every onion site and persist the emergency latch?")) return;
    await pending(button, "Stopping…", () => api("/api/emergency/stop"));
    return;
  }
  if (action === "emergency-clear") {
    await pending(button, "Restoring…", () => api("/api/emergency/clear"));
    return;
  }
  if (action === "wizard-bootstrap-open" || action === "wizard-bootstrap-extend") {
    await pending(button, "Opening…", async () => {
      const result = await api(`/api/sites/${encodeURIComponent(wizardSiteId)}/bootstrap/open`, { seconds: 900 });
      showBootstrap(result);
      showNotice("Certificate download is open for 15 minutes.");
    }, false);
    return;
  }
  if (action === "wizard-bootstrap-close") {
    await pending(button, "Closing…", async () => {
      await api(`/api/sites/${encodeURIComponent(wizardSiteId)}/bootstrap/close`);
      bootstrapExpiresUnix = null;
      stopBootstrapTimer();
      document.querySelector("#bootstrap-result").hidden = true;
      document.querySelector("#bootstrap-url").textContent = "";
      document.querySelector("#bootstrap-link").removeAttribute("href");
      document.querySelector("#bootstrap-qr").removeAttribute("src");
      document.querySelector("[data-action=wizard-bootstrap-open]").hidden = false;
      document.querySelector("[data-action=wizard-bootstrap-extend]").hidden = true;
      button.hidden = true;
      updateBootstrapCountdown();
      showNotice("Certificate download closed.");
    }, false);
    return;
  }
  if (action === "wizard-revoke-device" && wizardEnrollment) {
    if (!window.confirm("Revoke this device’s Tor authorization and unfinished enrollment?")) return;
    await pending(button, "Revoking…", () => api(
      `/api/sites/${encodeURIComponent(wizardSiteId)}/guests/${encodeURIComponent(wizardEnrollment.guest_id)}/devices/${encodeURIComponent(wizardEnrollment.device_id)}/revoke`,
    ));
    return;
  }
  if (action === "wizard-another-device") {
    deviceForm.reset();
    deviceForm.elements.site_id.value = wizardSiteId;
    clearDeviceResult();
    deviceForm.querySelector("input:not([type=hidden])")?.focus();
    document.querySelector("[data-step='2']").scrollIntoView({ behavior: "smooth", block: "start" });
    showNotice("Ready to create a separate authorization for another device.");
    return;
  }
});

for (const button of document.querySelectorAll("[data-component]")) {
  button.addEventListener("click", async () => {
    const component = button.dataset.component;
    const action = button.dataset.componentAction;
    await pending(button, `${action[0].toUpperCase()}${action.slice(1)}ing…`, () => api(`/api/components/${component}/${action}`));
  });
}

for (const button of document.querySelectorAll("[data-platform]")) {
  button.addEventListener("click", () => selectPlatform(button.dataset.platform));
}
