// Check Web Crypto availability and provide fallback
const subtle = (globalThis.crypto && (globalThis.crypto.subtle || globalThis.crypto.webkitSubtle)) || null;
if (!subtle) {
  console.error('Web Crypto API (SubtleCrypto) not available in this environment.');
  try {
    const chat = document.getElementById && document.getElementById('chatWindow');
    if (chat) {
      const msg = document.createElement('div');
      msg.className = 'message decrypted';
      msg.textContent = '⚠️ Your browser does not support the Web Crypto API required for encryption/decryption.';
      chat.appendChild(msg);
    }
  } catch (e) {
  }
}

// Derive a key from password
async function getKey(password, salt) {
  if (!subtle) throw new Error('Web Crypto SubtleCrypto is not available');
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
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
  if (!subtle) throw new Error('Web Crypto SubtleCrypto is not available');
  const key = await getKey(password, salt);
  const ciphertext = await subtle.encrypt(
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
    if (!subtle) throw new Error('Web Crypto SubtleCrypto is not available');
    const data = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    const key = await getKey(password, salt);
    const decrypted = await subtle.decrypt(
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

// Adds message bubble
function addMessage(text, type) {
  const chat = document.getElementById("chatWindow");
  const msg = document.createElement("div");
  msg.className = "message " + type;
  msg.textContent = text;
  chat.appendChild(msg);
  chat.scrollTop = chat.scrollHeight;
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


