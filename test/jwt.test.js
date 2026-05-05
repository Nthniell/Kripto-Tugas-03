const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { sign, verify } = require('../src/jwt');

function keyPair(namedCurve = 'prime256v1') {
  return crypto.generateKeyPairSync('ec', {
    namedCurve,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
}

const curveByAlg = {
  ES256: 'prime256v1',
  ES384: 'secp384r1',
  ES512: 'secp521r1'
};

test('sign and verify happy paths for ES256, ES384, and ES512', () => {
  for (const alg of Object.keys(curveByAlg)) {
    const { privateKey, publicKey } = keyPair(curveByAlg[alg]);
    const now = Math.floor(Date.now() / 1000);
    const jwt = sign({
      header: { alg, typ: 'JWT' },
      payload: { foo: 'bar' },
      claims: {
        iss: 'issuer',
        sub: 'subject',
        aud: 'audience',
        iat: now,
        nbf: now - 1,
        exp: now + 60,
        jti: `${alg}-id`
      },
      privateKey
    });
    const decoded = verify({
      jwt,
      publicKey,
      options: { algs: [alg], iss: 'issuer', sub: 'subject', aud: 'audience', jti: `${alg}-id` }
    });
    assert.equal(decoded.header.alg, alg);
    assert.equal(decoded.payload.foo, 'bar');
  }
});

test('claims override payload keys during sign', () => {
  const { privateKey, publicKey } = keyPair();
  const jwt = sign({
    header: { alg: 'ES256', typ: 'JWT' },
    payload: { sub: 'payload-sub', value: 7 },
    claims: { sub: 'claim-sub' },
    privateKey
  });
  const decoded = verify({ jwt, publicKey });
  assert.equal(decoded.payload.sub, 'claim-sub');
  assert.equal(decoded.payload.value, 7);
});

test('sign rejects invalid header', () => {
  const { privateKey } = keyPair();
  assert.throws(() => sign({ header: { alg: 'HS256', typ: 'JWT' }, payload: {}, privateKey }), /Unsupported/);
  assert.throws(() => sign({ header: { alg: 'ES256', typ: 'NOTJWT' }, payload: {}, privateKey }), /typ/);
});

test('sign rejects missing private key', () => {
  assert.throws(() => sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: {} }), /Private key/);
});

test('sign rejects non-object payload and claims', () => {
  const { privateKey } = keyPair();
  assert.throws(() => sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: null, privateKey }), /Payload/);
  assert.throws(() => sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: {}, claims: [], privateKey }), /Claims/);
});

test('verify rejects malformed JWT', () => {
  const { publicKey } = keyPair();
  assert.throws(() => verify({ jwt: 'abc.def', publicKey }), /format/);
  assert.throws(() => verify({ jwt: 'abc.def.ghi.jkl', publicKey }), /format/);
});

test('verify rejects tampered payload', () => {
  const { privateKey, publicKey } = keyPair();
  const jwt = sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: { ok: true }, privateKey });
  const parts = jwt.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ ok: false })).toString('base64url');
  assert.throws(() => verify({ jwt: `${parts[0]}.${tamperedPayload}.${parts[2]}`, publicKey }), /signature/);
});

test('verify rejects wrong public key', () => {
  const first = keyPair();
  const second = keyPair();
  const jwt = sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: { ok: true }, privateKey: first.privateKey });
  assert.throws(() => verify({ jwt, publicKey: second.publicKey }), /signature/);
});

test('verify rejects disallowed algorithm', () => {
  const { privateKey, publicKey } = keyPair();
  const jwt = sign({ header: { alg: 'ES256', typ: 'JWT' }, payload: {}, privateKey });
  assert.throws(() => verify({ jwt, publicKey, options: { algs: ['ES384'] } }), /not allowed/);
});

test('verify rejects expired and not-before tokens unless ignored', () => {
  const { privateKey, publicKey } = keyPair();
  const now = Math.floor(Date.now() / 1000);
  const expired = sign({
    header: { alg: 'ES256', typ: 'JWT' },
    payload: { exp: now - 1 },
    privateKey
  });
  assert.throws(() => verify({ jwt: expired, publicKey }), /expired/);
  assert.equal(verify({ jwt: expired, publicKey, options: { ignoreExp: true } }).payload.exp, now - 1);

  const future = sign({
    header: { alg: 'ES256', typ: 'JWT' },
    payload: { nbf: now + 60 },
    privateKey
  });
  assert.throws(() => verify({ jwt: future, publicKey }), /not active/);
  assert.equal(verify({ jwt: future, publicKey, options: { ignoreNbf: true } }).payload.nbf, now + 60);
});

test('verify rejects registered claim mismatches', () => {
  const { privateKey, publicKey } = keyPair();
  const jwt = sign({
    header: { alg: 'ES256', typ: 'JWT' },
    payload: { iss: 'a', sub: 'b', aud: ['web', 'api'], jti: 'id-1' },
    privateKey
  });
  assert.throws(() => verify({ jwt, publicKey, options: { iss: 'x' } }), /iss/);
  assert.throws(() => verify({ jwt, publicKey, options: { sub: 'x' } }), /sub/);
  assert.throws(() => verify({ jwt, publicKey, options: { aud: 'mobile' } }), /aud/);
  assert.throws(() => verify({ jwt, publicKey, options: { jti: 'id-2' } }), /jti/);
  assert.equal(verify({ jwt, publicKey, options: { aud: 'api' } }).payload.jti, 'id-1');
});
