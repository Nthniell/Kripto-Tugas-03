const crypto = require('crypto');

const ALG_PARAMS = {
  ES256: { curve: 'prime256v1', hash: 'SHA256', size: 32 },
  ES384: { curve: 'secp384r1', hash: 'SHA384', size: 48 },
  ES512: { curve: 'secp521r1', hash: 'SHA512', size: 66 }
};

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64urlDecode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('Invalid base64url value');
  }
  const pad = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function decodeJson(segment, label) {
  try {
    return JSON.parse(base64urlDecode(segment).toString('utf8'));
  } catch (error) {
    throw new Error(`Invalid JWT ${label}`);
  }
}

function assertSerializable(payload) {
  try {
    JSON.stringify(payload);
  } catch (error) {
    throw new Error('Payload must be JSON serializable');
  }
}

function validateHeader(header) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    throw new Error('Header must be an object');
  }
  if (header.typ !== 'JWT') {
    throw new Error('Header typ must be JWT');
  }
  if (!ALG_PARAMS[header.alg]) {
    throw new Error('Unsupported JWT algorithm');
  }
}

function sign({ header, claims = {}, payload = {}, privateKey }) {
  validateHeader(header);
  if (!privateKey) {
    throw new Error('Private key is required');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Payload must be an object');
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('Claims must be an object');
  }

  const mergedPayload = { ...payload, ...claims };
  assertSerializable(header);
  assertSerializable(mergedPayload);

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(mergedPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const params = ALG_PARAMS[header.alg];
  const signer = crypto.createSign(params.hash);
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${base64url(signature)}`;
}

function validateRegisteredClaims(payload, options) {
  const now = Math.floor(Date.now() / 1000);
  if (!options.ignoreExp && payload.exp !== undefined && now >= Number(payload.exp)) {
    throw new Error('JWT expired');
  }
  if (!options.ignoreNbf && payload.nbf !== undefined && now < Number(payload.nbf)) {
    throw new Error('JWT not active yet');
  }
  for (const claim of ['iss', 'sub', 'jti']) {
    if (options[claim] !== undefined && payload[claim] !== options[claim]) {
      throw new Error(`JWT ${claim} claim mismatch`);
    }
  }
  if (options.aud !== undefined) {
    const aud = payload.aud;
    const matches = Array.isArray(aud) ? aud.includes(options.aud) : aud === options.aud;
    if (!matches) {
      throw new Error('JWT aud claim mismatch');
    }
  }
}

function verify({ jwt, publicKey, options = {} }) {
  if (typeof jwt !== 'string') {
    throw new Error('JWT must be a string');
  }
  if (!publicKey) {
    throw new Error('Public key is required');
  }

  const parts = jwt.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error('Invalid JWT format');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = decodeJson(encodedHeader, 'header');
  const payload = decodeJson(encodedPayload, 'payload');
  validateHeader(header);

  if (options.algs !== undefined && !options.algs.includes(header.alg)) {
    throw new Error('JWT algorithm is not allowed');
  }

  const signature = base64urlDecode(encodedSignature);
  const params = ALG_PARAMS[header.alg];
  const expectedLength = params.size * 2;
  if (signature.length !== expectedLength) {
    throw new Error('Invalid JWT signature length');
  }

  const verifier = crypto.createVerify(params.hash);
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  const ok = verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
  if (!ok) {
    throw new Error('Invalid JWT signature');
  }

  validateRegisteredClaims(payload, options);
  return { header, payload, signature: encodedSignature };
}

module.exports = {
  sign,
  verify,
  base64url,
  base64urlDecode,
  ALG_PARAMS
};
