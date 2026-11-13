'use strict';

const { createProductionHandler, redactSecrets } = require('../server');

let cachedHandler = null;

function getHandler() {
  if (!cachedHandler) {
    cachedHandler = createProductionHandler();
  }
  return cachedHandler;
}

function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(payload));
}

module.exports = async function vercelByokHandler(req, res) {
  const rawUrl = String((req && req.url) || '/');
  const pathname = rawUrl.split('?')[0].replace(/\/+$/, '') || '/';
  const method = String((req && req.method) || 'GET').toUpperCase();

  try {
    const handler = getHandler();
    if (pathname === '/' && method === 'GET') {
      return sendJson(res, 200, { service: 'myhorloge-byok', status: 'ok' });
    }
    return await handler(req, res);
  } catch (err) {
    const safeMsg = redactSecrets((err && err.message) || 'BYOK initialization error');
    console.error('[Vercel BYOK Error]', safeMsg);
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
};
