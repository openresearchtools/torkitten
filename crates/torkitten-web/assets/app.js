(() => {
  "use strict";

  const decode = (value) => {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  };

  const encode = (value) => {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const creationOptions = (wrapper) => {
    const options = wrapper.publicKey;
    options.challenge = decode(options.challenge);
    options.user.id = decode(options.user.id);
    for (const descriptor of options.excludeCredentials || []) descriptor.id = decode(descriptor.id);
    return options;
  };

  const requestOptions = (wrapper) => {
    const options = wrapper.publicKey;
    options.challenge = decode(options.challenge);
    for (const descriptor of options.allowCredentials || []) descriptor.id = decode(descriptor.id);
    return options;
  };

  const registrationJSON = (credential) => ({
    id: credential.id,
    rawId: encode(credential.rawId),
    response: {
      attestationObject: encode(credential.response.attestationObject),
      clientDataJSON: encode(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults(),
  });

  const authenticationJSON = (credential) => ({
    id: credential.id,
    rawId: encode(credential.rawId),
    response: {
      authenticatorData: encode(credential.response.authenticatorData),
      clientDataJSON: encode(credential.response.clientDataJSON),
      signature: encode(credential.response.signature),
      userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults(),
  });

  const csrf = () => document.querySelector("[name=csrf]").value;

  const request = async (url, body = {}) => {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      redirect: "follow",
      headers: { "content-type": "application/json", "x-csrf-token": csrf() },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : {};
    payload.return_to = response.headers.get("x-torkitten-return-to");
    return payload;
  };

  const run = async (button, action) => {
    const status = document.querySelector("[data-passkey-status]");
    button.disabled = true;
    status.textContent = "Waiting for this device…";
    status.dataset.state = "pending";
    try {
      const returnTo = await action();
      status.textContent = "Passkey verified. Opening the site…";
      status.dataset.state = "success";
      window.location.assign(returnTo || "/");
    } catch (error) {
      status.textContent = error && error.name === "NotAllowedError"
        ? "The passkey request was cancelled or timed out. Try again."
        : "Passkey verification failed. Check this device and try again.";
      status.dataset.state = "failure";
      button.disabled = false;
    }
  };

  const enrollmentButton = document.querySelector("[data-passkey-enroll]");
  if (enrollmentButton) enrollmentButton.addEventListener("click", () => run(enrollmentButton, async () => {
    const base = window.location.pathname.replace(/\/$/, "");
    const started = await request(`${base}/passkey/start`);
    const credential = await navigator.credentials.create({ publicKey: creationOptions(started.public_key) });
    if (!credential) throw new Error("No passkey was created");
    const finished = await request(`${base}/passkey/finish`, {
      ceremony: started.ceremony,
      credential: registrationJSON(credential),
    });
    return finished.return_to;
  }));

  const loginButton = document.querySelector("[data-passkey-login]");
  if (loginButton) loginButton.addEventListener("click", () => run(loginButton, async () => {
    const guestId = document.querySelector("[data-passkey-guest]").value.trim();
    if (!guestId) throw new Error("Guest ID is required");
    const started = await request("/passkey/start", { guest_id: guestId });
    const credential = await navigator.credentials.get({ publicKey: requestOptions(started.public_key) });
    if (!credential) throw new Error("No passkey was selected");
    const finished = await request("/passkey/finish", {
      guest_id: guestId,
      ceremony: started.ceremony,
      credential: authenticationJSON(credential),
      return_to: document.querySelector("[data-return-to]")?.value || null,
      return_mapping: document.querySelector("[data-return-mapping]")?.value || null,
    });
    return finished.return_to;
  }));

  const logoutForm = document.querySelector("[data-logout]");
  if (logoutForm) logoutForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = logoutForm.querySelector("button[type=submit]");
    const status = logoutForm.querySelector("[data-logout-status]");
    button.disabled = true;
    status.textContent = "Signing out…";
    status.dataset.state = "pending";
    try {
      const response = await fetch(logoutForm.action, {
        method: "POST",
        credentials: "same-origin",
        redirect: "follow",
        body: new URLSearchParams(new FormData(logoutForm)),
      });
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      status.textContent = "Signed out.";
      status.dataset.state = "success";
      window.location.assign(response.url);
    } catch (_) {
      status.textContent = "Sign out failed. Check the connection and try again.";
      status.dataset.state = "failure";
      button.disabled = false;
    }
  });

  const revokeOtherSessionsForm = document.querySelector("[data-revoke-other-sessions]");
  if (revokeOtherSessionsForm) revokeOtherSessionsForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = revokeOtherSessionsForm.querySelector("button[type=submit]");
    const status = revokeOtherSessionsForm.querySelector("[data-revoke-other-sessions-status]");
    button.disabled = true;
    status.textContent = "Signing out other devices…";
    status.dataset.state = "pending";
    try {
      const response = await fetch(revokeOtherSessionsForm.action, {
        method: "POST",
        credentials: "same-origin",
        body: new URLSearchParams(new FormData(revokeOtherSessionsForm)),
      });
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      status.textContent = "Other devices are signed out. This session is still active.";
      status.dataset.state = "success";
      button.disabled = false;
    } catch (_) {
      status.textContent = "Could not sign out other devices. Check the connection and try again.";
      status.dataset.state = "failure";
      button.disabled = false;
    }
  });
})();
