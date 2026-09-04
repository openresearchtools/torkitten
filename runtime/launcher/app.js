"use strict";

const list = document.getElementById("applications");
const make = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};

fetch("/apps.json", {credentials: "same-origin"})
  .then(response => {
    if (!response.ok) throw new Error();
    return response.json();
  })
  .then(state => {
    list.replaceChildren();
    for (const app of state.apps || []) {
      const link = make("a", "application");
      link.href = app.url;
      const copy = make("span");
      copy.append(make("strong", "", app.name), make("small", "", app.url));
      link.append(copy, make("b", "", "→"));
      list.append(link);
    }
    if (!list.children.length) list.append(make("div", "empty", "No applications are available yet."));
  })
  .catch(() => list.replaceChildren(make("div", "empty", "Applications could not be loaded.")));

const profileButton = document.getElementById("apple-profile");
profileButton.addEventListener("click", async () => {
  const original = profileButton.textContent;
  profileButton.disabled = true;
  try {
    const response = await fetch("/trust/torkitten-root-ca.pem", {credentials: "same-origin"});
    if (!response.ok) throw new Error();
    const certificate = (await response.text()).replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
    const id = location.hostname.split(".")[0];
    if (!/^[a-z2-7]{56}$/.test(id) || !/^[A-Za-z0-9+/]+=*$/.test(certificate)) throw new Error();
    const fallbackUUID = suffix => {
      const value = [...id.slice(0, 15) + suffix].map(character => character.charCodeAt(0).toString(16)).join("").split("");
      value[12] = "5";
      value[16] = "8";
      const hex = value.join("");
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    };
    const rootUUID = crypto.randomUUID?.() || fallbackUUID("r");
    const profileUUID = crypto.randomUUID?.() || fallbackUUID("p");
    const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>Torkitten Root CA.cer</string>
<key>PayloadContent</key><data>${certificate}</data>
<key>PayloadDescription</key><string>Trust the private HTTPS certificate authority for this Torkitten onion service.</string>
<key>PayloadDisplayName</key><string>Torkitten Root CA</string>
<key>PayloadIdentifier</key><string>works.earendil.torkitten.${id}.root</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>${rootUUID}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDescription</key><string>Installs only this Torkitten instance's public root certificate.</string>
<key>PayloadDisplayName</key><string>Torkitten HTTPS Root</string>
<key>PayloadIdentifier</key><string>works.earendil.torkitten.${id}</string>
<key>PayloadOrganization</key><string>Torkitten</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>${profileUUID}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>`;
    const url = URL.createObjectURL(new Blob([profile], {type: "application/x-apple-aspen-config"}));
    const download = make("a");
    download.href = url;
    download.download = "torkitten-ios.mobileconfig";
    download.click();
    profileButton.textContent = "Profile downloaded";
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (_) {
    profileButton.textContent = "Download failed";
  } finally {
    profileButton.disabled = false;
    window.setTimeout(() => { profileButton.textContent = original; }, 2500);
  }
});
