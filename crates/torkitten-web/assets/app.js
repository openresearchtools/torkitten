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

  const preferAuthenticator = (options, preference, creating) => {
    options.hints = [preference === "security-key" ? "security-key" : "client-device"];
    if (creating) {
      options.authenticatorSelection = {
        ...(options.authenticatorSelection || {}),
        authenticatorAttachment: preference === "security-key" ? "cross-platform" : "platform",
      };
    }
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

  const runPasskey = async (button, action) => {
    const panel = button.closest(".passkey-panel");
    const status = panel.querySelector("[data-passkey-status]");
    const buttons = panel.querySelectorAll("[data-passkey-enroll], [data-passkey-login]");
    for (const candidate of buttons) candidate.disabled = true;
    status.textContent = button.dataset.passkeyEnroll === "security-key" || button.dataset.passkeyLogin === "security-key"
      ? "Waiting for the hardware security key…"
      : "Waiting for this device…";
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
      for (const candidate of buttons) candidate.disabled = false;
    }
  };

  for (const enrollmentButton of document.querySelectorAll("[data-passkey-enroll]")) {
    enrollmentButton.addEventListener("click", () => runPasskey(enrollmentButton, async () => {
      const preference = enrollmentButton.dataset.passkeyEnroll;
      const base = window.location.pathname.replace(/\/$/, "");
      const started = await request(`${base}/passkey/start`);
      const options = preferAuthenticator(creationOptions(started.public_key), preference, true);
      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) throw new Error("No passkey was created");
      const finished = await request(`${base}/passkey/finish`, {
        ceremony: started.ceremony,
        credential: registrationJSON(credential),
      });
      return finished.return_to;
    }));
  }

  for (const loginButton of document.querySelectorAll("[data-passkey-login]")) {
    loginButton.addEventListener("click", () => runPasskey(loginButton, async () => {
      const preference = loginButton.dataset.passkeyLogin;
      const panel = loginButton.closest(".passkey-panel");
      const guestInput = panel.querySelector("[data-passkey-guest]");
      if (!guestInput.reportValidity()) throw new Error("Guest ID is required");
      const guestId = guestInput.value.trim();
      const started = await request("/passkey/start", { guest_id: guestId });
      const options = preferAuthenticator(requestOptions(started.public_key), preference, false);
      const credential = await navigator.credentials.get({ publicKey: options });
      if (!credential) throw new Error("No passkey was selected");
      const finished = await request("/passkey/finish", {
        guest_id: guestId,
        ceremony: started.ceremony,
        credential: authenticationJSON(credential),
        return_to: panel.querySelector("[data-return-to]")?.value || null,
        return_mapping: panel.querySelector("[data-return-mapping]")?.value || null,
      });
      return finished.return_to;
    }));
  }

  const passwordForm = document.querySelector("[data-password-login]");
  if (passwordForm) {
    const passwordStep = passwordForm.querySelector("[data-password-step]");
    const totpStep = passwordForm.querySelector("[data-totp-step]");
    const guestInput = passwordForm.querySelector("[name=guest_id]");
    const passwordInput = passwordForm.querySelector("[name=password]");
    const totpInput = passwordForm.querySelector("[name=totp_code]");
    const status = passwordForm.querySelector("[data-password-status]");
    let challenge = null;

    const showPasswordStep = () => {
      challenge = null;
      passwordInput.value = "";
      totpInput.value = "";
      guestInput.disabled = false;
      passwordInput.disabled = false;
      totpInput.disabled = true;
      passwordStep.hidden = false;
      totpStep.hidden = true;
      status.textContent = "";
      delete status.dataset.state;
      guestInput.focus();
    };

    passwordForm.querySelector("[data-password-back]").addEventListener("click", showPasswordStep);
    passwordForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || (challenge ? totpStep : passwordStep).querySelector("button[type=submit]");
      submit.disabled = true;
      if (!challenge) {
        status.textContent = "Checking password…";
        status.dataset.state = "pending";
        try {
          const started = await request("/login/password", {
            guest_id: guestInput.value.trim(),
            password: passwordInput.value,
          });
          if (!started.challenge) throw new Error("No authentication challenge was issued");
          challenge = started.challenge;
          passwordInput.value = "";
          guestInput.disabled = true;
          passwordInput.disabled = true;
          totpInput.disabled = false;
          passwordStep.hidden = true;
          totpStep.hidden = false;
          status.textContent = "Password accepted.";
          status.dataset.state = "success";
          totpInput.focus();
        } catch (_) {
          status.textContent = "Password was not accepted. Check the guest ID and try again.";
          status.dataset.state = "failure";
        } finally {
          submit.disabled = false;
        }
        return;
      }

      status.textContent = "Checking authenticator code…";
      status.dataset.state = "pending";
      try {
        const finished = await request("/login/totp", {
          challenge,
          totp_code: totpInput.value,
          return_to: passwordForm.querySelector("[data-return-to]")?.value || null,
          return_mapping: passwordForm.querySelector("[data-return-mapping]")?.value || null,
        });
        totpInput.value = "";
        status.textContent = "Signed in. Opening the site…";
        status.dataset.state = "success";
        window.location.assign(finished.return_to || "/");
      } catch (_) {
        showPasswordStep();
        status.textContent = "The authenticator code was not accepted. Start again to retry.";
        status.dataset.state = "failure";
      } finally {
        submit.disabled = false;
      }
    });
  }

  const enrollmentForm = document.querySelector("[data-password-enrollment]");
  if (enrollmentForm) {
    const passwordStep = enrollmentForm.querySelector("[data-enrollment-password-step]");
    const totpStep = enrollmentForm.querySelector("[data-enrollment-totp-step]");
    const passwordInput = enrollmentForm.querySelector("[name=password]");
    const totpInput = enrollmentForm.querySelector("[name=totp_code]");
    const next = enrollmentForm.querySelector("[data-enrollment-next]");
    const back = enrollmentForm.querySelector("[data-enrollment-back]");
    next.addEventListener("click", () => {
      if (!passwordInput.reportValidity()) return;
      passwordStep.hidden = true;
      totpStep.hidden = false;
      totpInput.disabled = false;
      totpInput.focus();
    });
    back.addEventListener("click", () => {
      totpInput.value = "";
      totpInput.disabled = true;
      totpStep.hidden = true;
      passwordStep.hidden = false;
      passwordInput.focus();
    });
  }

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
