'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');

const {
  createByokHandler,
  createEnvelopeCipher,
  createFirestoreEncryptedVaultStore,
  createInMemoryEncryptedVaultStore,
  createSecretManagerVaultStore,
  createProductionHandler,
  normalizeMasterKey,
  parseServiceAccountJson,
  resolveFirestoreDatabaseId,
  redactSecrets
} = require('./server');

async function startTestServer(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

test('master key validation rejects missing key and fails decryption with wrong master key', () => {
  assert.throws(() => normalizeMasterKey(''), /required/i);
  assert.throws(() => normalizeMasterKey(undefined), /required/i);
  assert.throws(() => normalizeMasterKey(Buffer.alloc(16)), /32 bytes/i);

  const keyA = crypto.randomBytes(32);
  const keyB = crypto.randomBytes(32);
  const cipherA = createEnvelopeCipher(keyA);
  const cipherB = createEnvelopeCipher(keyB);

  const secret = 'AIzaSyTestUserSecretKey12345678901234';
  const envelope = cipherA.encryptForUser('uid_alice', secret);

  assert.equal(envelope.maskedKey, 'AIza••••1234');
  assert.ok(!JSON.stringify(envelope).includes(secret), 'Envelope must never contain plaintext API key');
  assert.equal(cipherA.decryptForUser('uid_alice', envelope), secret);

  // Wrong master key must fail GCM authentication
  assert.throws(
    () => cipherB.decryptForUser('uid_alice', envelope),
    /Unsupported state or unable to authenticate data/
  );

  // Wrong UID must fail AAD authentication even with right master key
  assert.throws(
    () => cipherA.decryptForUser('uid_bob', envelope),
    /Unsupported state or unable to authenticate data/
  );
});

test('Firestore database validation blocks missing or (default) database without revealing secrets', () => {
  assert.throws(() => resolveFirestoreDatabaseId({}), /must be explicitly configured/i);
  assert.throws(
    () => resolveFirestoreDatabaseId({ FIRESTORE_DATABASE_ID: '(default)' }),
    /cannot be empty or "\(default\)"/i
  );

  const sensitiveMistake = 'AIzaSyAccidentalSecretInEnv123456789012';
  let invalidErr = null;
  try {
    resolveFirestoreDatabaseId({ FIRESTORE_DATABASE_ID: sensitiveMistake });
  } catch (err) {
    invalidErr = err;
  }
  assert.ok(invalidErr);
  assert.ok(!invalidErr.message.includes(sensitiveMistake), 'Error must not echo invalid value/secret');

  const namedDb = 'ai-studio-android-myhorlog-d8ba217e-6e58-45bc-8987-2b39682ec708';
  assert.equal(resolveFirestoreDatabaseId({ FIRESTORE_DATABASE_ID: namedDb }), namedDb);

  const fakeAdmin = {
    apps: [],
    initializeApp() {},
    auth() {
      return { verifyIdToken: async () => ({ uid: 'u1' }) };
    }
  };
  let capturedDbId = null;
  const fakeFirestoreModule = {
    getFirestore(dbId) {
      capturedDbId = dbId;
      return { collection: () => ({ doc: () => ({}) }) };
    }
  };

  assert.throws(
    () =>
      createProductionHandler({
        env: {
          GOOGLE_CLOUD_PROJECT: 'gen-lang-client-0987408187',
          BYOK_STORAGE_MODE: 'firestore-encrypted',
          BYOK_VAULT_MASTER_KEY: crypto.randomBytes(32).toString('hex')
        },
        adminModule: fakeAdmin,
        firestoreModule: fakeFirestoreModule
      }),
    /FIRESTORE_DATABASE_ID/
  );

  assert.throws(
    () =>
      createProductionHandler({
        env: {
          GOOGLE_CLOUD_PROJECT: 'gen-lang-client-0987408187',
          BYOK_STORAGE_MODE: 'invalid-mode'
        },
        adminModule: fakeAdmin,
        firestoreModule: fakeFirestoreModule
      }),
    /BYOK_STORAGE_MODE/
  );

  const prodHandler = createProductionHandler({
    env: {
      GOOGLE_CLOUD_PROJECT: 'gen-lang-client-0987408187',
      BYOK_STORAGE_MODE: 'firestore-encrypted',
      FIRESTORE_DATABASE_ID: namedDb,
      BYOK_FIRESTORE_COLLECTION: 'byok_vault_encrypted',
      BYOK_VAULT_MASTER_KEY: crypto.randomBytes(32).toString('hex')
    },
    adminModule: fakeAdmin,
    firestoreModule: fakeFirestoreModule
  });
  assert.equal(typeof prodHandler, 'function');
  assert.equal(capturedDbId, namedDb);
});

test('Firestore encrypted vault adapter stores encrypted envelopes only and deletes documents', async () => {
  const cipher = createEnvelopeCipher(crypto.randomBytes(32));
  const collections = new Map();
  const fakeDb = {
    collection(colName) {
      if (!collections.has(colName)) collections.set(colName, new Map());
      const docs = collections.get(colName);
      return {
        doc(docId) {
          return {
            async set(data) {
              docs.set(docId, data);
            },
            async get() {
              if (!docs.has(docId)) return { exists: false, data: () => undefined };
              return { exists: true, data: () => docs.get(docId) };
            },
            async delete() {
              docs.delete(docId);
            }
          };
        }
      };
    }
  };

  const store = createFirestoreEncryptedVaultStore({
    firestoreDb: fakeDb,
    collectionName: 'byok_vault_encrypted',
    cipher
  });

  const secret = 'AIzaSyFirestoreAdapterTestKey1234567890';
  const masked = await store.saveKey('uid_fs_1', secret);
  assert.equal(masked, 'AIza••••7890');

  const rawDoc = collections.get('byok_vault_encrypted').get('uid_fs_1');
  assert.ok(rawDoc);
  assert.equal(rawDoc.alg, 'AES-256-GCM-HKDF');
  assert.ok(!JSON.stringify(rawDoc).includes(secret), 'Plaintext key must never appear in Firestore doc');

  assert.equal(await store.getKey('uid_fs_1'), secret);
  assert.equal(await store.getKey('uid_fs_other'), null);

  await store.deleteKey('uid_fs_1');
  assert.equal(collections.get('byok_vault_encrypted').has('uid_fs_1'), false);
  assert.equal(await store.getKey('uid_fs_1'), null);
});

test('Secret Manager vault adapter creates, versions, reads, handles ALREADY_EXISTS/NOT_FOUND, and deletes', async () => {
  const secrets = new Map();
  let createCalls = 0;

  const fakeClient = {
    async createSecret({ parent, secretId }) {
      createCalls += 1;
      const fullName = `${parent}/secrets/${secretId}`;
      if (secrets.has(fullName)) {
        const err = new Error('Already exists');
        err.code = 6;
        throw err;
      }
      secrets.set(fullName, []);
    },
    async addSecretVersion({ parent, payload }) {
      if (!secrets.has(parent)) {
        const err = new Error('Not found');
        err.code = 5;
        throw err;
      }
      secrets.get(parent).push(Buffer.from(payload.data));
    },
    async accessSecretVersion({ name }) {
      const secretPath = name.replace(/\/versions\/latest$/, '');
      const versions = secrets.get(secretPath);
      if (!versions || versions.length === 0) {
        const err = new Error('Not found');
        err.code = 5;
        throw err;
      }
      return [{ payload: { data: versions.at(-1) } }];
    },
    async deleteSecret({ name }) {
      if (!secrets.has(name)) {
        const err = new Error('Not found');
        err.code = 5;
        throw err;
      }
      secrets.delete(name);
    }
  };

  const store = createSecretManagerVaultStore({
    projectId: 'gen-lang-client-0987408187',
    client: fakeClient
  });

  const secretV1 = 'AIzaSySecretManagerKeyV1_12345678901234';
  const secretV2 = 'AIzaSySecretManagerKeyV2_98765432109876';

  assert.equal(await store.getKey('uid_sm_1'), null);
  assert.equal(await store.saveKey('uid_sm_1', secretV1), 'AIza••••1234');
  // Secret ID must not expose raw UID
  const storedName = [...secrets.keys()][0];
  assert.ok(!storedName.includes('uid_sm_1'));

  // Updating key hits ALREADY_EXISTS (code 6) cleanly and appends new version
  assert.equal(await store.saveKey('uid_sm_1', secretV2), 'AIza••••9876');
  assert.equal(createCalls, 2);
  assert.equal(await store.getKey('uid_sm_1'), secretV2);

  await store.deleteKey('uid_sm_1');
  assert.equal(await store.getKey('uid_sm_1'), null);
  // Deleting again tolerates NOT_FOUND (code 5)
  await store.deleteKey('uid_sm_1');
});

test('BYOK HTTP endpoints enforce auth, input validation, secret redaction, models, and deletion', async () => {
  const cipher = createEnvelopeCipher(crypto.randomBytes(32));
  const vaultStore = createInMemoryEncryptedVaultStore(cipher);
  const loggedErrors = [];
  const upstreamCalls = [];

  const aliceKey = 'AIzaSyAlicePersonalGeminiKey9876543210';

  const fakeUpstreamFetch = async (url, options) => {
    upstreamCalls.push({ url, method: options.method, headers: options.headers, body: options.body });
    if (url.endsWith('/v1beta/models')) {
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            models: [
              { name: 'models/gemini-2.5-flash', supportedGenerationMethods: ['generateContent'] },
              { name: 'models/gemini-3.8-flash', supportedGenerationMethods: ['generateContent'] },
              { name: 'models/gemini-1.5-flash', supportedGenerationMethods: ['generateContent'] },
              { name: 'models/text-embedding-004', supportedGenerationMethods: ['embedContent'] }
            ]
          });
        }
      };
    }
    if (url.includes(':generateContent')) {
      const parsedBody = JSON.parse(options.body || '{}');
      const promptText = parsedBody?.contents?.[0]?.parts?.[0]?.text || '';
      if (promptText === 'TRIGGER_UPSTREAM_503_LEAK') {
        return {
          ok: false,
          status: 503,
          async text() {
            return JSON.stringify({
              error: {
                message: `Key ${aliceKey} failed for x-goog-api-key: ${aliceKey} and ?key=${aliceKey} with Bearer secret_jwt_token`
              }
            });
          }
        };
      }
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [
                    { text: JSON.stringify({ reply: 'Alarme à 19:00', actionType: 'CREATE_ALARM', hour: 19, minute: 0 }) }
                  ]
                }
              }
            ]
          });
        }
      };
    }
    return { ok: false, status: 404, async text() { return '{}'; } };
  };

  const tokenToUid = {
    token_alice: 'uid_alice',
    token_bob: 'uid_bob'
  };

  const handler = createByokHandler({
    verifyIdToken: async (token) => {
      if (token === 'token_no_uid') return {};
      const uid = tokenToUid[token];
      if (!uid) throw new Error('Invalid token');
      return { uid };
    },
    vaultStore,
    upstreamFetch: fakeUpstreamFetch,
    logger: {
      error: (...args) => loggedErrors.push(args.join(' '))
    }
  });

  const { baseUrl, close } = await startTestServer(handler);
  try {
    // 1. GET /healthz is open without auth
    const health = await fetch(`${baseUrl}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });

    // 2. Missing, malformed, invalid, and UID-less Firebase tokens -> 401 across endpoints
    const authChecks = [
      { path: '/byok/test', method: 'POST', headers: {} },
      { path: '/byok/models', method: 'GET', headers: { Authorization: 'Basic abc123' } },
      { path: '/byok/key', method: 'POST', headers: { Authorization: 'Bearer   ' } },
      { path: '/byok/generate', method: 'POST', headers: { Authorization: 'Bearer bad_token' } },
      { path: '/byok/key', method: 'DELETE', headers: { Authorization: 'Bearer token_no_uid' } }
    ];
    for (const check of authChecks) {
      const resp = await fetch(`${baseUrl}${check.path}`, {
        method: check.method,
        headers: check.headers
      });
      assert.equal(resp.status, 401, `Expected 401 for ${check.method} ${check.path}`);
    }

    // 3. Invalid Gemini API key -> 400 and nothing vaulted
    const badKeyResp = await fetch(`${baseUrl}/byok/key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer token_alice'
      },
      body: JSON.stringify({ apiKey: 'not-a-gemini-key' })
    });
    assert.equal(badKeyResp.status, 400);
    assert.equal(vaultStore._rawEnvelopes.has('uid_alice'), false);

    // 4. Register Alice's valid key
    const regResp = await fetch(`${baseUrl}/byok/key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer token_alice'
      },
      body: JSON.stringify({ apiKey: aliceKey })
    });
    assert.equal(regResp.status, 200);
    assert.equal((await regResp.json()).maskedKey, 'AIza••••3210');

    // Stored envelope contains zero plaintext
    const storedEnvelope = vaultStore._rawEnvelopes.get('uid_alice');
    assert.ok(storedEnvelope);
    assert.ok(!JSON.stringify(storedEnvelope).includes(aliceKey));

    // 5. Bob cannot access Alice's key on /byok/models or /byok/test
    assert.equal(
      (await fetch(`${baseUrl}/byok/models`, { headers: { Authorization: 'Bearer token_bob' } })).status,
      404
    );
    assert.equal(
      (await fetch(`${baseUrl}/byok/test`, { method: 'POST', headers: { Authorization: 'Bearer token_bob' } })).status,
      404
    );

    // 6. GET /byok/models returns only modern text Gemini models
    const modelsResp = await fetch(`${baseUrl}/byok/models`, {
      headers: { Authorization: 'Bearer token_alice' }
    });
    assert.equal(modelsResp.status, 200);
    const modelsJson = await modelsResp.json();
    assert.deepEqual(modelsJson.models, ['gemini-2.5-flash', 'gemini-3.8-flash']);

    // 7. POST /byok/test selects preferred modern model
    const aliceTest = await fetch(`${baseUrl}/byok/test`, {
      method: 'POST',
      headers: { Authorization: 'Bearer token_alice' }
    });
    assert.equal(aliceTest.status, 200);
    assert.equal((await aliceTest.json()).activeModel, 'gemini-3.8-flash');

    // 8. Invalid Gemini model rejected with 400 before any upstream call
    const upstreamCountBeforeInvalid = upstreamCalls.length;
    for (const invalidModel of ['gpt-4o', '../secrets', 'gemini-2.5-flash/../../x']) {
      const badModelResp = await fetch(`${baseUrl}/byok/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer token_alice'
        },
        body: JSON.stringify({
          model: invalidModel,
          contents: [{ parts: [{ text: 'hello' }] }]
        })
      });
      assert.equal(badModelResp.status, 400, `Expected 400 for invalid model ${invalidModel}`);
    }
    assert.equal(upstreamCalls.length, upstreamCountBeforeInvalid);

    // 9. Valid /byok/generate attaches x-goog-api-key only server-side
    const genResp = await fetch(`${baseUrl}/byok/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer token_alice'
      },
      body: JSON.stringify({
        model: 'gemini-2.5-flash',
        contents: [{ parts: [{ text: 'Crée une alarme à 19 h' }] }]
      })
    });
    assert.equal(genResp.status, 200);
    const genJson = await genResp.json();
    assert.equal(JSON.parse(genJson.text).hour, 19);
    assert.equal(upstreamCalls.at(-1).headers['x-goog-api-key'], aliceKey);

    // 10. Upstream 5xx/4xx secrets are redacted from response and logs
    const leakResp = await fetch(`${baseUrl}/byok/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer token_alice'
      },
      body: JSON.stringify({
        model: 'gemini-2.5-flash',
        contents: [{ parts: [{ text: 'TRIGGER_UPSTREAM_503_LEAK' }] }]
      })
    });
    assert.equal(leakResp.status, 503);
    const leakText = await leakResp.text();
    assert.ok(!leakText.includes(aliceKey), 'Response must redact Gemini API key');
    assert.ok(!leakText.includes('secret_jwt_token'), 'Response must redact Bearer token');
    assert.ok(leakText.includes('[REDACTED_GEMINI_KEY]'));
    assert.ok(leakText.includes('Bearer [REDACTED_TOKEN]'));
    assert.ok(!loggedErrors.join('\n').includes(aliceKey));

    // Also verify redactSecrets handles JSON {"apiKey":"..."}
    const redactedObj = redactSecrets(`{"apiKey":"${aliceKey}"}`);
    assert.ok(!redactedObj.includes(aliceKey));

    // 11. DELETE /byok/key deletes the stored key across all subsequent endpoints
    const delResp = await fetch(`${baseUrl}/byok/key`, {
      method: 'DELETE',
      headers: { Authorization: 'Bearer token_alice' }
    });
    assert.equal(delResp.status, 200);
    assert.equal(vaultStore._rawEnvelopes.has('uid_alice'), false);

    assert.equal(
      (await fetch(`${baseUrl}/byok/test`, { method: 'POST', headers: { Authorization: 'Bearer token_alice' } })).status,
      404
    );
    assert.equal(
      (await fetch(`${baseUrl}/byok/models`, { headers: { Authorization: 'Bearer token_alice' } })).status,
      404
    );
    assert.equal(
      (
        await fetch(`${baseUrl}/byok/generate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer token_alice'
          },
          body: JSON.stringify({
            model: 'gemini-2.5-flash',
            contents: [{ parts: [{ text: 'hello' }] }]
          })
        })
      ).status,
      404
    );
  } finally {
    await close();
  }
});

test('Vercel compatibility: pre-parsed req.body, /api prefix, and FIREBASE_SERVICE_ACCOUNT_JSON', async () => {
  // 1. parseServiceAccountJson handles raw JSON (with escaped \\n), base64 JSON, and rejects malformed input
  const sampleSa = {
    project_id: 'gen-lang-client-0987408187',
    client_email: 'firebase-adminsdk@gen-lang-client-0987408187.iam.gserviceaccount.com',
    private_key: '-----BEGIN PRIVATE KEY-----\\nTEST_KEY_LINE\\n-----END PRIVATE KEY-----\\n'
  };
  const parsedRaw = parseServiceAccountJson(JSON.stringify(sampleSa));
  assert.equal(parsedRaw.project_id, 'gen-lang-client-0987408187');
  assert.ok(parsedRaw.private_key.includes('\nTEST_KEY_LINE\n'));

  const encodedB64 = Buffer.from(JSON.stringify(sampleSa), 'utf8').toString('base64');
  const parsedB64 = parseServiceAccountJson(encodedB64);
  assert.equal(parsedB64.client_email, sampleSa.client_email);

  const badSecretInput = 'secret_private_key_must_not_leak';
  assert.throws(
    () => parseServiceAccountJson(badSecretInput),
    (err) => err.message.includes('invalid or malformed') && !err.message.includes(badSecretInput)
  );

  // 2. createProductionHandler wires credential.cert when FIREBASE_SERVICE_ACCOUNT_JSON is set
  let initializedWith = null;
  const fakeAdmin = {
    apps: [],
    credential: {
      cert(obj) {
        return { _certEmail: obj.client_email };
      }
    },
    initializeApp(opts) {
      initializedWith = opts;
    },
    auth() {
      return { verifyIdToken: async () => ({ uid: 'uid_vercel' }) };
    }
  };
  const fakeFirestoreModule = {
    getFirestore() {
      return { collection: () => ({ doc: () => ({}) }) };
    }
  };

  createProductionHandler({
    env: {
      FIREBASE_SERVICE_ACCOUNT_JSON: JSON.stringify(sampleSa),
      FIRESTORE_DATABASE_ID: 'ai-studio-android-myhorlog-d8ba217e-6e58-45bc-8987-2b39682ec708',
      BYOK_VAULT_MASTER_KEY: crypto.randomBytes(32).toString('hex')
    },
    adminModule: fakeAdmin,
    firestoreModule: fakeFirestoreModule
  });
  assert.equal(initializedWith.projectId, 'gen-lang-client-0987408187');
  assert.equal(initializedWith.credential._certEmail, sampleSa.client_email);

  // 3. Handler handles pre-parsed req.body (Vercel runtime) and /api/* prefix cleanly
  const cipher = createEnvelopeCipher(crypto.randomBytes(32));
  const vaultStore = createInMemoryEncryptedVaultStore(cipher);
  const handler = createByokHandler({
    verifyIdToken: async (token) => (token === 'vercel_tok' ? { uid: 'uid_vercel' } : Promise.reject(new Error('bad'))),
    vaultStore
  });

  function createMockRes() {
    return {
      statusCode: 0,
      headers: {},
      body: '',
      writeHead(code, headers) {
        this.statusCode = code;
        this.headers = headers;
      },
      end(chunk) {
        this.body = String(chunk || '');
      }
    };
  }

  const healthRes = createMockRes();
  await handler({ method: 'GET', url: '/api/healthz', headers: {} }, healthRes);
  assert.equal(healthRes.statusCode, 200);
  assert.deepEqual(JSON.parse(healthRes.body), { status: 'ok' });

  const preParsedKey = 'AIzaSyVercelPreParsedBodyKey1234567890';
  const postRes = createMockRes();
  await handler(
    {
      method: 'POST',
      url: '/api/byok/key',
      headers: { authorization: 'Bearer vercel_tok' },
      body: { apiKey: preParsedKey }
    },
    postRes
  );
  assert.equal(postRes.statusCode, 200);
  assert.equal(JSON.parse(postRes.body).maskedKey, 'AIza••••7890');
  assert.equal(await vaultStore.getKey('uid_vercel'), preParsedKey);

  // 4. api/index.js returns safe 503 JSON diagnostics (no crash / no secret leak) when env vars are missing
  const prevDbId = process.env.FIRESTORE_DATABASE_ID;
  const prevMaster = process.env.BYOK_VAULT_MASTER_KEY;
  delete process.env.FIRESTORE_DATABASE_ID;
  delete process.env.BYOK_VAULT_MASTER_KEY;
  try {
    const vercelEntry = require('./api/index.js');
    const diagRes = {
      statusCode: 0,
      headers: {},
      body: '',
      setHeader(k, v) {
        this.headers[k] = v;
      },
      end(chunk) {
        this.body = String(chunk || '');
      }
    };
    await vercelEntry({ method: 'GET', url: '/healthz', headers: {} }, diagRes);
    assert.equal(diagRes.statusCode, 503);
    const diagJson = JSON.parse(diagRes.body);
    assert.equal(diagJson.status, 'misconfigured');
    assert.equal(diagJson.checks.hasFirestoreDatabaseId, false);
    assert.equal(diagJson.checks.hasMasterKey, false);

    // 5. server.js itself is directly callable as a Vercel root entrypoint function
    const directServerEntry = require('./server.js');
    assert.equal(typeof directServerEntry, 'function');
    const directRes = {
      statusCode: 0,
      headers: {},
      body: '',
      writeHead(code, headers) {
        this.statusCode = code;
        this.headers = headers;
      },
      end(chunk) {
        this.body = String(chunk || '');
      }
    };
    await directServerEntry({ method: 'GET', url: '/', headers: {} }, directRes);
    assert.equal(directRes.statusCode, 503);
    assert.equal(JSON.parse(directRes.body).status, 'misconfigured');
  } finally {
    if (prevDbId !== undefined) process.env.FIRESTORE_DATABASE_ID = prevDbId;
    if (prevMaster !== undefined) process.env.BYOK_VAULT_MASTER_KEY = prevMaster;
  }
});
