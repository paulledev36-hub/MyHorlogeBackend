'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const GOOGLE_AI_STUDIO_ORIGIN = 'https://generativelanguage.googleapis.com';
const MAX_JSON_BODY_BYTES = 1024 * 1024; // 1 MB
const API_KEY_PATTERN = /^(?:AIza[0-9A-Za-z_-]{20,}|AQ\.[0-9A-Za-z_.-]{20,})$/;
const MODEL_NAME_PATTERN = /^gemini-[a-z0-9._-]{2,64}$/i;
const MODERN_PREFERRED_MODELS = [
  'gemini-3.8-flash',
  'gemini-3.5-flash-lite',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite'
];

function redactSecrets(text) {
  if (!text) return '';
  return String(text)
    .replace(/(?:AIza[0-9A-Za-z_-]{10,}|AQ\.[0-9A-Za-z_.-]{10,})/g, '[REDACTED_GEMINI_KEY]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/(x-goog-api-key\s*[:=]\s*)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/([?&]key=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/("apiKey"\s*:\s*")[^"]+(")/gi, '$1[REDACTED]$2');
}

function maskApiKey(apiKey) {
  if (!apiKey || apiKey.length < 10) return '••••';
  return `${apiKey.slice(0, 4)}••••${apiKey.slice(-4)}`;
}

function isModernGeminiTextModel(name) {
  const lower = String(name || '').toLowerCase();
  if (!lower.startsWith('gemini-')) return false;
  const excluded = ['1.0', '1.5', '2.0', 'embedding', 'imagen', 'veo', 'tts', 'audio', 'live'];
  return !excluded.some((token) => lower.includes(token));
}

function pickPreferredActiveModel(availableModels) {
  for (const preferred of MODERN_PREFERRED_MODELS) {
    if (availableModels.includes(preferred)) return preferred;
  }
  return availableModels[0] || 'gemini-2.5-flash';
}

/**
 * Derives a user-bound 256-bit key using HKDF-SHA256 from the server master key,
 * then seals the personal Gemini API key with AES-256-GCM and AAD = `myhorloge:byok:${uid}`.
 * Plaintext keys are never written to Firestore or logs.
 */
function createEnvelopeCipher(masterKeyInput) {
  const masterKey = normalizeMasterKey(masterKeyInput);

  function deriveUserKey(uid) {
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        masterKey,
        Buffer.from(`myhorloge-salt:${uid}`, 'utf8'),
        Buffer.from('myhorloge-byok-envelope-v1', 'utf8'),
        32
      )
    );
  }

  return {
    encryptForUser(uid, plaintextKey) {
      const key = deriveUserKey(uid);
      const iv = crypto.randomBytes(12);
      const aad = Buffer.from(`uid:${uid}`, 'utf8');
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([
        cipher.update(plaintextKey, 'utf8'),
        cipher.final()
      ]);
      const tag = cipher.getAuthTag();
      return {
        v: 1,
        alg: 'AES-256-GCM-HKDF',
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        maskedKey: maskApiKey(plaintextKey),
        updatedAtMs: Date.now()
      };
    },

    decryptForUser(uid, envelope) {
      if (!envelope || envelope.v !== 1 || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
        throw new Error('Malformed encrypted key envelope');
      }
      const key = deriveUserKey(uid);
      const iv = Buffer.from(envelope.iv, 'base64');
      const tag = Buffer.from(envelope.tag, 'base64');
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
      const aad = Buffer.from(`uid:${uid}`, 'utf8');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      return plaintext.toString('utf8');
    }
  };
}

function normalizeMasterKey(masterKeyInput) {
  if (Buffer.isBuffer(masterKeyInput)) {
    if (masterKeyInput.length !== 32) {
      throw new Error('BYOK_VAULT_MASTER_KEY buffer must be 32 bytes');
    }
    return masterKeyInput;
  }
  const raw = String(masterKeyInput || '').trim();
  if (!raw) {
    throw new Error('BYOK_VAULT_MASTER_KEY environment secret is required');
  }
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  const base64Buf = Buffer.from(raw, 'base64');
  if (base64Buf.length === 32) {
    return base64Buf;
  }
  // Fallback: domain-separated SHA-256 stretch for passphrase-style dev secrets
  return crypto.createHash('sha256').update(`myhorloge-master:${raw}`, 'utf8').digest();
}

/**
 * Firestore encrypted-envelope store:
 * Stores ONLY AES-256-GCM encrypted envelopes (`iv`, `tag`, `ciphertext`, `maskedKey`)
 * keyed strictly by verified `uid` — NEVER plaintext keys.
 */
function createFirestoreEncryptedVaultStore({ firestoreDb, collectionName, cipher }) {
  return {
    async saveKey(uid, apiKey) {
      const envelope = cipher.encryptForUser(uid, apiKey);
      await firestoreDb.collection(collectionName).doc(uid).set(envelope);
      return envelope.maskedKey;
    },
    async getKey(uid) {
      const snap = await firestoreDb.collection(collectionName).doc(uid).get();
      if (!snap.exists) return null;
      const envelope = snap.data();
      return cipher.decryptForUser(uid, envelope);
    },
    async deleteKey(uid) {
      await firestoreDb.collection(collectionName).doc(uid).delete();
    }
  };
}

/**
 * Google Cloud Secret Manager store (zero secret material in Firestore).
 */
function createSecretManagerVaultStore({ projectId, secretPrefix = 'myhorloge-byok-', client }) {
  const smClient = client || (() => {
    const secretManagerPkg = '@google-cloud/secret-manager';
    const { SecretManagerServiceClient } = require(secretManagerPkg);
    return new SecretManagerServiceClient();
  })();
  const safeSecretId = (uid) => {
    const hash = crypto.createHash('sha256').update(uid, 'utf8').digest('hex').slice(0, 32);
    return `${secretPrefix}${hash}`;
  };
  return {
    async saveKey(uid, apiKey) {
      const secretId = safeSecretId(uid);
      const parent = `projects/${projectId}`;
      const secretPath = `${parent}/secrets/${secretId}`;
      try {
        await smClient.createSecret({
          parent,
          secretId,
          secret: { replication: { automatic: {} } }
        });
      } catch (err) {
        if (err.code !== 6) throw err; // 6 = ALREADY_EXISTS
      }
      await smClient.addSecretVersion({
        parent: secretPath,
        payload: { data: Buffer.from(apiKey, 'utf8') }
      });
      return maskApiKey(apiKey);
    },
    async getKey(uid) {
      const secretId = safeSecretId(uid);
      const name = `projects/${projectId}/secrets/${secretId}/versions/latest`;
      try {
        const [version] = await smClient.accessSecretVersion({ name });
        return version.payload.data.toString('utf8');
      } catch (err) {
        if (err.code === 5) return null; // 5 = NOT_FOUND
        throw err;
      }
    },
    async deleteKey(uid) {
      const secretId = safeSecretId(uid);
      const name = `projects/${projectId}/secrets/${secretId}`;
      try {
        await smClient.deleteSecret({ name });
      } catch (err) {
        if (err.code !== 5) throw err;
      }
    }
  };
}

function createInMemoryEncryptedVaultStore(cipher) {
  const map = new Map();
  return {
    _rawEnvelopes: map,
    async saveKey(uid, apiKey) {
      const envelope = cipher.encryptForUser(uid, apiKey);
      map.set(uid, envelope);
      return envelope.maskedKey;
    },
    async getKey(uid) {
      const envelope = map.get(uid);
      if (!envelope) return null;
      return cipher.decryptForUser(uid, envelope);
    },
    async deleteKey(uid) {
      map.delete(uid);
    }
  };
}

async function readJsonBody(req) {
  if (req && req.body !== undefined) {
    if (Buffer.isBuffer(req.body)) {
      if (req.body.length === 0) return {};
      if (req.body.length > MAX_JSON_BODY_BYTES) {
        throw Object.assign(new Error('Request body too large'), { statusCode: 413 });
      }
      try {
        return JSON.parse(req.body.toString('utf8'));
      } catch {
        throw Object.assign(new Error('Invalid JSON payload'), { statusCode: 400 });
      }
    }
    if (typeof req.body === 'string') {
      if (Buffer.byteLength(req.body, 'utf8') > MAX_JSON_BODY_BYTES) {
        throw Object.assign(new Error('Request body too large'), { statusCode: 413 });
      }
      if (!req.body.trim()) return {};
      try {
        return JSON.parse(req.body);
      } catch {
        throw Object.assign(new Error('Invalid JSON payload'), { statusCode: 400 });
      }
    }
    if (typeof req.body === 'object' && req.body !== null) {
      return req.body;
    }
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_JSON_BODY_BYTES) {
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON payload'), { statusCode: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  };
  if (typeof res.writeHead === 'function') {
    res.writeHead(statusCode, headers);
  } else {
    res.statusCode = statusCode;
    if (typeof res.setHeader === 'function') {
      for (const [k, v] of Object.entries(headers)) {
        res.setHeader(k, v);
      }
    }
  }
  res.end(body);
}

/**
 * Creates an HTTP request handler implementing the MyHorloge BYOK server contract:
 * - POST   /byok/key
 * - DELETE /byok/key
 * - POST   /byok/test
 * - GET    /byok/models
 * - POST   /byok/generate
 * - GET    /healthz
 */
function createByokHandler({
  verifyIdToken,
  vaultStore,
  upstreamFetch = globalThis.fetch,
  logger = console
}) {
  if (typeof verifyIdToken !== 'function') {
    throw new Error('verifyIdToken function is required');
  }
  if (!vaultStore) {
    throw new Error('vaultStore is required');
  }

  async function authenticate(req) {
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader || typeof authHeader !== 'string') {
      throw Object.assign(new Error('Missing Firebase Authorization Bearer token.'), { statusCode: 401 });
    }
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match || !match[1].trim()) {
      throw Object.assign(new Error('Invalid Authorization Bearer header.'), { statusCode: 401 });
    }
    try {
      const decoded = await verifyIdToken(match[1].trim());
      if (!decoded || !decoded.uid) {
        throw new Error('Token missing uid claim');
      }
      return decoded.uid;
    } catch {
      throw Object.assign(new Error('Invalid or expired Firebase ID Token.'), { statusCode: 401 });
    }
  }

  async function fetchGeminiModels(personalKey) {
    const resp = await upstreamFetch(`${GOOGLE_AI_STUDIO_ORIGIN}/v1beta/models`, {
      method: 'GET',
      headers: {
        'x-goog-api-key': personalKey
      }
    });
    const text = await resp.text();
    if (!resp.ok) {
      throw Object.assign(new Error(redactSecrets(text || `Gemini error ${resp.status}`)), {
        statusCode: resp.status
      });
    }
    const parsed = JSON.parse(text || '{}');
    const rawModels = Array.isArray(parsed.models) ? parsed.models : [];
    const filtered = [];
    for (const entry of rawModels) {
      const name = String(entry?.name || '').replace(/^models\//, '');
      const methods = Array.isArray(entry?.supportedGenerationMethods)
        ? entry.supportedGenerationMethods
        : ['generateContent'];
      if (isModernGeminiTextModel(name) && methods.includes('generateContent')) {
        filtered.push(name);
      }
    }
    return [...new Set(filtered)];
  }

  return async function handleByokRequest(req, res) {
    const parsedUrl = new URL(req.url || '/', 'http://localhost');
    let pathname = parsedUrl.pathname.replace(/\/+$/, '') || '/';
    if (pathname === '/api/healthz' || pathname.startsWith('/api/byok/')) {
      pathname = pathname.slice(4);
    }
    const method = (req.method || 'GET').toUpperCase();

    if (method === 'GET' && pathname === '/healthz') {
      return sendJson(res, 200, { status: 'ok' });
    }

    try {
      const uid = await authenticate(req);

      if (pathname === '/byok/key' && method === 'POST') {
        const body = await readJsonBody(req);
        const apiKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
        if (!API_KEY_PATTERN.test(apiKey)) {
          return sendJson(res, 400, { message: 'Clé Google Gemini invalide.' });
        }
        const maskedKey = await vaultStore.saveKey(uid, apiKey);
        return sendJson(res, 200, { maskedKey, status: 'vaulted' });
      }

      if (pathname === '/byok/key' && method === 'DELETE') {
        await vaultStore.deleteKey(uid);
        return sendJson(res, 200, { status: 'deleted' });
      }

      if (pathname === '/byok/models' && method === 'GET') {
        const personalKey = await vaultStore.getKey(uid);
        if (!personalKey) {
          return sendJson(res, 404, { message: 'No personal key registered for this user.' });
        }
        const models = await fetchGeminiModels(personalKey);
        return sendJson(res, 200, { models });
      }

      if (pathname === '/byok/test' && method === 'POST') {
        const personalKey = await vaultStore.getKey(uid);
        if (!personalKey) {
          return sendJson(res, 404, { message: 'No personal key registered for this user.' });
        }
        const models = await fetchGeminiModels(personalKey);
        const activeModel = pickPreferredActiveModel(models);
        return sendJson(res, 200, { activeModel });
      }

      if (pathname === '/byok/generate' && method === 'POST') {
        const personalKey = await vaultStore.getKey(uid);
        if (!personalKey) {
          return sendJson(res, 404, { message: 'No personal key registered for this user.' });
        }
        const body = await readJsonBody(req);
        const requestedModel = String(body.model || 'gemini-2.5-flash').replace(/^models\//, '');
        if (!MODEL_NAME_PATTERN.test(requestedModel)) {
          return sendJson(res, 400, { message: 'Invalid Gemini model name.' });
        }
        if (!Array.isArray(body.contents) || body.contents.length === 0) {
          return sendJson(res, 400, { message: 'Request contents are required.' });
        }

        const upstreamPayload = {
          contents: body.contents,
          ...(body.generationConfig ? { generationConfig: body.generationConfig } : {})
        };

        const upstreamResp = await upstreamFetch(
          `${GOOGLE_AI_STUDIO_ORIGIN}/v1beta/models/${encodeURIComponent(requestedModel)}:generateContent`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-goog-api-key': personalKey
            },
            body: JSON.stringify(upstreamPayload)
          }
        );

        const upstreamText = await upstreamResp.text();
        if (!upstreamResp.ok) {
          return sendJson(res, upstreamResp.status, {
            message: redactSecrets(upstreamText || `Gemini error ${upstreamResp.status}`)
          });
        }

        const parsed = JSON.parse(upstreamText || '{}');
        const extractedText = parsed?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        return sendJson(res, 200, {
          text: extractedText,
          candidates: parsed.candidates || []
        });
      }

      return sendJson(res, 404, { message: 'Route not found' });
    } catch (err) {
      const status = err.statusCode || 500;
      if (status >= 500 && logger && typeof logger.error === 'function') {
        logger.error('[BYOK Server Error]', redactSecrets(err.message || String(err)));
      }
      return sendJson(res, status, {
        message: redactSecrets(err.message || 'Internal BYOK server error')
      });
    }
  };
}

function resolveFirestoreDatabaseId(env = process.env) {
  const raw = String(env.FIRESTORE_DATABASE_ID || '').trim();
  if (!raw || raw === '(default)') {
    throw new Error(
      'FIRESTORE_DATABASE_ID must be explicitly configured (cannot be empty or "(default)") in firestore-encrypted mode.'
    );
  }
  if (!/^[a-z0-9-]{4,63}$/.test(raw)) {
    throw new Error(
      'FIRESTORE_DATABASE_ID has an invalid format; expected a named Firestore database ID.'
    );
  }
  return raw;
}

function parseServiceAccountJson(rawValue) {
  const trimmed = String(rawValue || '').trim();
  if (!trimmed) return null;
  let parsed;
  try {
    const jsonText = trimmed.startsWith('{')
      ? trimmed
      : Buffer.from(trimmed, 'base64').toString('utf8');
    parsed = JSON.parse(jsonText);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is invalid or malformed.');
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.client_email || !parsed.private_key) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is missing required service account fields.');
  }
  if (typeof parsed.private_key === 'string' && parsed.private_key.includes('\\n')) {
    parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
  }
  return parsed;
}

function createProductionHandler({ env = process.env, adminModule, firestoreModule } = {}) {
  const admin = adminModule || require('firebase-admin');
  const serviceAccount = parseServiceAccountJson(env.FIREBASE_SERVICE_ACCOUNT_JSON);
  const explicitProjectId =
    env.GOOGLE_CLOUD_PROJECT ||
    env.GCLOUD_PROJECT ||
    env.GCP_PROJECT ||
    (serviceAccount && serviceAccount.project_id);
  if (!Array.isArray(admin.apps) || admin.apps.length === 0) {
    const initOptions = {};
    if (explicitProjectId) initOptions.projectId = explicitProjectId;
    if (serviceAccount && admin.credential && typeof admin.credential.cert === 'function') {
      initOptions.credential = admin.credential.cert(serviceAccount);
    }
    admin.initializeApp(Object.keys(initOptions).length > 0 ? initOptions : undefined);
  }
  const auth = admin.auth();
  const projectId = explicitProjectId || (admin.app && admin.app().options && admin.app().options.projectId);
  const storageMode = String(env.BYOK_STORAGE_MODE || 'firestore-encrypted').trim().toLowerCase();
  if (storageMode !== 'firestore-encrypted' && storageMode !== 'secret-manager') {
    throw new Error('BYOK_STORAGE_MODE must be either "firestore-encrypted" or "secret-manager".');
  }

  let vaultStore;
  if (storageMode === 'secret-manager') {
    if (!projectId) {
      throw new Error('GOOGLE_CLOUD_PROJECT is required when BYOK_STORAGE_MODE=secret-manager.');
    }
    vaultStore = createSecretManagerVaultStore({ projectId });
  } else {
    const databaseId = resolveFirestoreDatabaseId(env);
    const cipher = createEnvelopeCipher(env.BYOK_VAULT_MASTER_KEY);
    const { getFirestore } = firestoreModule || require('firebase-admin/firestore');
    const firestoreDb = getFirestore(databaseId);
    const collectionName = String(env.BYOK_FIRESTORE_COLLECTION || 'byok_vault_encrypted').trim() || 'byok_vault_encrypted';
    vaultStore = createFirestoreEncryptedVaultStore({ firestoreDb, collectionName, cipher });
  }

  return createByokHandler({
    verifyIdToken: (idToken) => auth.verifyIdToken(idToken, true),
    vaultStore
  });
}

let cachedEntrypointHandler = null;

async function vercelOrServerlessEntrypoint(req, res) {
  const rawUrl = String((req && req.url) || '/');
  const pathname = rawUrl.split('?')[0].replace(/\/+$/, '') || '/';
  const method = String((req && req.method) || 'GET').toUpperCase();

  try {
    if (!cachedEntrypointHandler) {
      cachedEntrypointHandler = createProductionHandler();
    }
    if (pathname === '/' && method === 'GET') {
      return sendJson(res, 200, { service: 'myhorloge-byok', status: 'ok' });
    }
    return await cachedEntrypointHandler(req, res);
  } catch (err) {
    const safeMsg = redactSecrets((err && err.message) || 'BYOK initialization error');
    console.error('[BYOK Server Error]', safeMsg);
    if (pathname === '/healthz' || pathname === '/api/healthz' || pathname === '/') {
      return sendJson(res, 503, {
        status: 'misconfigured',
        message: safeMsg,
        checks: {
          hasMasterKey: Boolean(String(process.env.BYOK_VAULT_MASTER_KEY || '').trim()),
          hasFirestoreDatabaseId: Boolean(String(process.env.FIRESTORE_DATABASE_ID || '').trim()),
          hasServiceAccountJson: Boolean(String(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || '').trim()),
          storageMode: String(process.env.BYOK_STORAGE_MODE || 'firestore-encrypted')
        }
      });
    }
    return sendJson(res, 500, { message: safeMsg });
  }
}

if (require.main === module) {
  const port = Number(process.env.PORT || 8080);
  const host = '0.0.0.0';
  const handler = createProductionHandler();
  const server = http.createServer(handler);
  server.listen(port, host, () => {
    console.log(`MyHorloge secure BYOK server listening on ${host}:${port}`);
  });
  process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
  });
}

module.exports = Object.assign(vercelOrServerlessEntrypoint, {
  createByokHandler,
  createEnvelopeCipher,
  createFirestoreEncryptedVaultStore,
  createInMemoryEncryptedVaultStore,
  createSecretManagerVaultStore,
  createProductionHandler,
  normalizeMasterKey,
  parseServiceAccountJson,
  resolveFirestoreDatabaseId,
  redactSecrets,
  maskApiKey
});
