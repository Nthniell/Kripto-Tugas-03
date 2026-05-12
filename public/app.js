const state = {
  mode: 'login',
  token: localStorage.getItem('token') || '',
  email: '',
  privateKey: null,
  contacts: [],
  activeContact: null,
  activeKeys: null,
  poller: null
};

const $ = (id) => document.getElementById(id);

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function randomBase64(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase64(bytes);
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle('error', isError);
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }
  return data;
}

async function derivePasswordKey(password, saltBase64, iterations) {
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: base64ToBytes(saltBase64),
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPrivateKey(privateKey, password) {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  const salt = randomBase64(16);
  const iv = randomBase64(12);
  const iterations = 150000;
  const aesKey = await derivePasswordKey(password, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: base64ToBytes(iv) }, aesKey, pkcs8);
  return {
    type: 'pkcs8',
    kdf: 'PBKDF2',
    hash: 'SHA-256',
    iterations,
    aes: 'AES-256-GCM',
    salt,
    iv,
    ciphertext: bytesToBase64(ciphertext)
  };
}

async function decryptPrivateKey(envelope, password) {
  const aesKey = await derivePasswordKey(password, envelope.salt, envelope.iterations);
  const pkcs8 = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(envelope.iv) },
    aesKey,
    base64ToBytes(envelope.ciphertext)
  );
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}

async function generateChatIdentity(password) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privateKeyEnvelope = await encryptPrivateKey(pair.privateKey, password);
  return { publicKeyJwk, privateKeyEnvelope };
}

function roomSalt(emailA, emailB) {
  return enc.encode([emailA, emailB].sort().join('|'));
}

async function deriveConversationKeys(contact) {
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    contact.publicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, state.privateKey, 256);
  console.log(`Shared Secret ${state.email} <-> ${contact.email}:`,bytesToBase64(sharedBits));
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const salt = roomSalt(state.email, contact.email);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('kripto-chat aes v1') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const macKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('kripto-chat mac v1') },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  );
  return { aesKey, macKey };
}

function macInput(message) {
  return enc.encode([
    message.senderEmail,
    message.receiverEmail,
    message.iv,
    message.ciphertext,
    message.timestamp
  ].join('|'));
}

async function encryptMessage(plaintext) {
  const iv = randomBase64(12);
  const timestamp = new Date().toISOString();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: base64ToBytes(iv) },
    state.activeKeys.aesKey,
    enc.encode(plaintext)
  );
  const message = {
    receiverEmail: state.activeContact.email,
    senderEmail: state.email,
    ciphertext: bytesToBase64(ciphertext),
    iv,
    timestamp
  };
  const mac = await crypto.subtle.sign('HMAC', state.activeKeys.macKey, macInput(message));
  return { ...message, mac: bytesToBase64(mac), alg: 'AES-256-GCM+HMAC-SHA-256' };
}

async function decryptMessage(message) {
  const macOk = await crypto.subtle.verify(
    'HMAC',
    state.activeKeys.macKey,
    base64ToBytes(message.mac),
    macInput(message)
  );
  if (!macOk) {
    return { text: '[MAC tidak valid]', invalid: true };
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(message.iv) },
      state.activeKeys.aesKey,
      base64ToBytes(message.ciphertext)
    );
    return { text: dec.decode(plaintext), invalid: false };
  } catch (error) {
    return { text: '[Pesan tidak dapat didekripsi]', invalid: true };
  }
}

function renderContacts() {
  const container = $('contacts');
  container.innerHTML = '';
  if (state.contacts.length === 0) {
    container.innerHTML = '<p class="status">Belum ada kontak lain.</p>';
    return;
  }
  for (const contact of state.contacts) {
    const button = document.createElement('button');
    button.className = `contact ${state.activeContact?.email === contact.email ? 'active' : ''}`;
    button.type = 'button';
    button.textContent = contact.email;
    button.addEventListener('click', () => selectContact(contact));
    container.append(button);
  }
}

async function renderMessages(messages) {
  const container = $('messages');
  container.innerHTML = '';
  if (!state.activeContact) {
    container.innerHTML = '<p class="empty">Pilih kontak untuk memulai percakapan.</p>';
    return;
  }
  if (messages.length === 0) {
    container.innerHTML = '<p class="empty">Belum ada pesan.</p>';
    return;
  }
  for (const message of messages) {
    const decrypted = await decryptMessage(message);
    const bubble = document.createElement('article');
    const direction = message.senderEmail === state.email ? 'sent' : 'received';
    bubble.className = `message ${direction} ${decrypted.invalid ? 'invalid' : ''}`;
    const text = document.createElement('p');
    text.textContent = decrypted.text;
    const meta = document.createElement('small');
    meta.textContent = `${message.senderEmail} · ${new Date(message.timestamp).toLocaleString('id-ID')}`;
    bubble.append(text, meta);
    container.append(bubble);
  }
  container.scrollTop = container.scrollHeight;
}

async function loadContacts() {
  const data = await api('/api/contacts');
  state.contacts = data.contacts;
  renderContacts();
}

async function loadMessages() {
  if (!state.activeContact) {
    await renderMessages([]);
    return;
  }
  const data = await api(`/api/messages?with=${encodeURIComponent(state.activeContact.email)}`);
  await renderMessages(data.messages);
}

async function selectContact(contact) {
  state.activeContact = contact;
  $('activeContact').textContent = contact.email;
  $('messageInput').disabled = false;
  $('sendButton').disabled = false;
  setStatus($('chatStatus'), 'Membentuk kunci komunikasi...');
  state.activeKeys = await deriveConversationKeys(contact);
  setStatus($('chatStatus'), 'Kunci komunikasi siap. Server hanya menerima ciphertext dan MAC.');
  renderContacts();
  await loadMessages();
}

function showChat() {
  $('authPanel').classList.add('hidden');
  $('chatApp').classList.remove('hidden');
  $('currentUser').textContent = state.email;
  if (!state.poller) {
    state.poller = setInterval(() => {
      loadMessages().catch(() => {});
    }, 2500);
  }
}

function showAuth() {
  $('chatApp').classList.add('hidden');
  $('authPanel').classList.remove('hidden');
  if (state.poller) {
    clearInterval(state.poller);
    state.poller = null;
  }
}

function setMode(mode) {
  state.mode = mode;
  $('loginTab').classList.toggle('active', mode === 'login');
  $('registerTab').classList.toggle('active', mode === 'register');
  $('authSubmit').textContent = mode === 'login' ? 'Login' : 'Register';
  setStatus($('authStatus'), '');
}

async function handleAuth(event) {
  event.preventDefault();
  const email = $('emailInput').value.trim().toLowerCase();
  const password = $('passwordInput').value;
  $('authSubmit').disabled = true;
  try {
    if (state.mode === 'register') {
      setStatus($('authStatus'), 'Membangkitkan pasangan kunci ECDH dan mengenkripsi private key...');
      const identity = await generateChatIdentity(password);
      await api('/api/register', {
        method: 'POST',
        body: JSON.stringify({ email, password, ...identity })
      });
      setMode('login');
      setStatus($('authStatus'), 'Registrasi berhasil. Silakan login.');
      return;
    }

    setStatus($('authStatus'), 'Memverifikasi password dan memulihkan private key...');
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    state.token = data.token;
    localStorage.setItem('token', state.token);
    state.email = data.user.email;
    state.privateKey = await decryptPrivateKey(data.user.privateKeyEnvelope, password);
    showChat();
    await loadContacts();
    await loadMessages();
  } catch (error) {
    setStatus($('authStatus'), error.message, true);
  } finally {
    $('authSubmit').disabled = false;
  }
}

async function handleSend(event) {
  event.preventDefault();
  const plaintext = $('messageInput').value.trim();
  if (!plaintext || !state.activeContact) {
    return;
  }
  $('sendButton').disabled = true;
  try {
    const message = await encryptMessage(plaintext);
    await api('/api/messages', { method: 'POST', body: JSON.stringify(message) });
    $('messageInput').value = '';
    await loadMessages();
    setStatus($('chatStatus'), 'Pesan terkirim sebagai ciphertext.');
  } catch (error) {
    setStatus($('chatStatus'), error.message, true);
  } finally {
    $('sendButton').disabled = false;
  }
}

function logout() {
  localStorage.removeItem('token');
  Object.assign(state, {
    token: '',
    email: '',
    privateKey: null,
    contacts: [],
    activeContact: null,
    activeKeys: null
  });
  $('passwordInput').value = '';
  $('messageInput').disabled = true;
  $('sendButton').disabled = true;
  $('messages').innerHTML = '';
  showAuth();
}

$('loginTab').addEventListener('click', () => setMode('login'));
$('registerTab').addEventListener('click', () => setMode('register'));
$('authForm').addEventListener('submit', handleAuth);
$('messageForm').addEventListener('submit', handleSend);
$('refreshContacts').addEventListener('click', () => loadContacts().catch((error) => setStatus($('chatStatus'), error.message, true)));
$('logoutButton').addEventListener('click', logout);

showAuth();
