// Utility: derive a crypto key from a password
async function getKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt message
async function encryptMessage(message, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(message)
  );
  const data = new Uint8Array([...salt, ...iv, ...new Uint8Array(ciphertext)]);
  return btoa(String.fromCharCode(...data));
}

// Decrypt message
async function decryptMessage(ciphertextB64, password) {
  try {
    const data = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    const key = await getKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  } catch (e) {
    return "❌ Wrong password or corrupted data";
  }
}

// UI: Add message bubble
function addMessage(text, type) {
  const chat = document.getElementById("chatWindow");
  const msg = document.createElement("div");
  msg.className = "message " + type;
  msg.textContent = text;
  chat.appendChild(msg);
  chat.scrollTop = chat.scrollHeight; // auto-scroll to bottom
}

// Encrypt button handler
document.getElementById("encryptBtn").addEventListener("click", async () => {
  const msg = document.getElementById("message").value.trim();
  const pwd = document.getElementById("password").value.trim();
  if (!msg || !pwd) return alert("Enter a message and password!");
  const encrypted = await encryptMessage(msg, pwd);
  addMessage(encrypted, "encrypted");
  document.getElementById("message").value = "";
});

// Decrypt button handler
document.getElementById("decryptBtn").addEventListener("click", async () => {
  const encrypted = document.getElementById("message").value.trim();
  const pwd = document.getElementById("password").value.trim();
  if (!encrypted || !pwd) return alert("Enter encrypted text and password!");
  const decrypted = await decryptMessage(encrypted, pwd);
  addMessage(decrypted, "decrypted");
  document.getElementById("message").value = "";
});


