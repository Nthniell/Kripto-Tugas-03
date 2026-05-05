const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sign, verify } = require('./src/jwt');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const PRIVATE_KEY_PATH = path.join(DATA_DIR, 'jwt-private.pem');
const PUBLIC_KEY_PATH = path.join(DATA_DIR, 'jwt-public.pem');
const PUBLIC_DIR = path.join(__dirname, 'public');

function ensureDataFiles() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], messages: [] }, null, 2));
  }
  if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);
  }
}

function readDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  });
  res.end(data);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('base64')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('base64');
  return { salt, hash };
}

function passwordsMatch(password, salt, expectedHash) {
  const actual = Buffer.from(hashPassword(password, salt).hash, 'base64');
  const expected = Buffer.from(expectedHash, 'base64');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function publicUser(user) {
  return {
    email: user.email,
    publicKeyJwk: user.publicKeyJwk
  };
}

function privateUser(user) {
  return {
    email: user.email,
    publicKeyJwk: user.publicKeyJwk,
    privateKeyEnvelope: user.privateKeyEnvelope
  };
}

function issueToken(user) {
  const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  const now = Math.floor(Date.now() / 1000);
  return sign({
    header: { alg: 'ES256', typ: 'JWT' },
    payload: { role: 'user' },
    claims: {
      iss: 'kripto-tugas-03',
      sub: user.email,
      aud: 'kripto-chat',
      iat: now,
      nbf: now,
      exp: now + 24 * 60 * 60,
      jti: crypto.randomUUID()
    },
    privateKey
  });
}

function authenticate(req) {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) {
    throw new Error('Missing bearer token');
  }
  const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const decoded = verify({
    jwt: token,
    publicKey,
    options: {
      algs: ['ES256'],
      iss: 'kripto-tugas-03',
      aud: 'kripto-chat'
    }
  });
  const db = readDb();
  const user = db.users.find((item) => item.email === decoded.payload.sub);
  if (!user) {
    throw new Error('Authenticated user not found');
  }
  return { db, user };
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const requested = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.normalize(path.join(PUBLIC_DIR, requested));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }
  const ext = path.extname(filePath);
  const contentTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8'
  };
  res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'application/octet-stream' });
  fs.createReadStream(filePath).pipe(res);
}

async function handleApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'POST' && url.pathname === '/api/register') {
    const body = await parseBody(req);
    const email = normalizeEmail(body.email);
    if (!email || !body.password || !body.publicKeyJwk || !body.privateKeyEnvelope) {
      return sendJson(res, 400, { error: 'Email, password, public key, and encrypted private key are required' });
    }
    const db = readDb();
    if (db.users.some((user) => user.email === email)) {
      return sendJson(res, 409, { error: 'Email is already registered' });
    }
    const password = hashPassword(body.password);
    db.users.push({
      id: crypto.randomUUID(),
      email,
      passwordSalt: password.salt,
      passwordHash: password.hash,
      publicKeyJwk: body.publicKeyJwk,
      privateKeyEnvelope: body.privateKeyEnvelope,
      createdAt: new Date().toISOString()
    });
    writeDb(db);
    return sendJson(res, 201, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/login') {
    const body = await parseBody(req);
    const email = normalizeEmail(body.email);
    const db = readDb();
    const user = db.users.find((item) => item.email === email);
    if (!user || !passwordsMatch(body.password || '', user.passwordSalt, user.passwordHash)) {
      return sendJson(res, 401, { error: 'Invalid email or password' });
    }
    return sendJson(res, 200, {
      token: issueToken(user),
      user: privateUser(user)
    });
  }

  if (url.pathname === '/api/me' && req.method === 'GET') {
    const { user } = authenticate(req);
    return sendJson(res, 200, { user: privateUser(user) });
  }

  if (url.pathname === '/api/contacts' && req.method === 'GET') {
    const { db, user } = authenticate(req);
    return sendJson(res, 200, {
      contacts: db.users.filter((item) => item.email !== user.email).map(publicUser)
    });
  }

  if (url.pathname === '/api/messages' && req.method === 'GET') {
    const { db, user } = authenticate(req);
    const other = normalizeEmail(url.searchParams.get('with'));
    const messages = db.messages.filter((message) => {
      return (
        (message.senderEmail === user.email && message.receiverEmail === other) ||
        (message.senderEmail === other && message.receiverEmail === user.email)
      );
    });
    return sendJson(res, 200, { messages });
  }

  if (url.pathname === '/api/messages' && req.method === 'POST') {
    const { db, user } = authenticate(req);
    const body = await parseBody(req);
    const receiverEmail = normalizeEmail(body.receiverEmail);
    if (!db.users.some((item) => item.email === receiverEmail)) {
      return sendJson(res, 404, { error: 'Receiver not found' });
    }
    for (const key of ['ciphertext', 'iv', 'mac', 'timestamp']) {
      if (!body[key]) {
        return sendJson(res, 400, { error: `Missing ${key}` });
      }
    }
    const message = {
      id: crypto.randomUUID(),
      senderEmail: user.email,
      receiverEmail,
      ciphertext: body.ciphertext,
      iv: body.iv,
      mac: body.mac,
      timestamp: body.timestamp,
      alg: body.alg || 'AES-256-GCM+HMAC-SHA-256'
    };
    db.messages.push(message);
    writeDb(db);
    return sendJson(res, 201, { message });
  }

  return sendJson(res, 404, { error: 'API route not found' });
}

ensureDataFiles();

const server = http.createServer(async (req, res) => {
  try {
    if (req.url.startsWith('/api/')) {
      await handleApi(req, res);
    } else {
      serveStatic(req, res);
    }
  } catch (error) {
    const status = /token|JWT|Authenticated/i.test(error.message) ? 401 : 400;
    sendJson(res, status, { error: error.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Kripto chat running at http://${HOST}:${PORT}`);
});
