(function () {
  var root = document.getElementById("passkey-root");
  if (!root) return;

  var button = root.querySelector("button");
  var statusEl = root.querySelector(".status");
  var csrf = document.querySelector('meta[name="csrf-token"]').content;
  var mode = root.dataset.mode; // "register" or "authenticate"

  if (!window.PublicKeyCredential || !navigator.credentials) {
    setStatus("This browser doesn't support passkeys. Try a current version of Chrome, Edge, Safari or Firefox.", true);
    button.disabled = true;
    return;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.className = "status" + (isError ? " error" : "");
  }

  function b64uToBuf(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    var padded = base64 + "===".slice((base64.length + 3) % 4);
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64u(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function post(url, body) {
    var response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify(body || {})
    });
    var data = {};
    try { data = await response.json(); } catch (e) { /* non-JSON error body */ }
    if (!response.ok) throw new Error(data.error || "Request failed (" + response.status + ")");
    return data;
  }

  async function register() {
    var begin = await post(root.dataset.begin);
    var options = begin.publicKey;
    options.challenge = b64uToBuf(options.challenge);
    options.user.id = b64uToBuf(options.user.id);
    (options.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });

    var cred = await navigator.credentials.create({ publicKey: options });
    return post(root.dataset.complete, {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject)
      }
    });
  }

  async function authenticate() {
    var begin = await post(root.dataset.begin);
    var options = begin.publicKey;
    options.challenge = b64uToBuf(options.challenge);
    (options.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });

    var cred = await navigator.credentials.get({ publicKey: options });
    var handle = cred.response.userHandle;
    return post(root.dataset.complete, {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        signature: bufToB64u(cred.response.signature),
        userHandle: handle ? bufToB64u(handle) : null
      }
    });
  }

  button.addEventListener("click", async function () {
    button.disabled = true;
    setStatus(mode === "register" ? "Follow your device prompt to create a passkey..." : "Follow your device prompt to verify...", false);
    try {
      var result = mode === "register" ? await register() : await authenticate();
      setStatus("Done.", false);
      window.location.href = result.redirect || root.dataset.next;
    } catch (err) {
      var cancelled = err && err.name === "NotAllowedError";
      setStatus(cancelled ? "The passkey prompt was cancelled or timed out. Try again." : err.message, true);
      button.disabled = false;
    }
  });
})();
