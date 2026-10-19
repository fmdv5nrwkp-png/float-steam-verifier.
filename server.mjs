import http from 'node:http';
import crypto from 'node:crypto';

const STEAM_ENDPOINT = 'https://steamcommunity.com/openid/login';
const CALLBACK_ORIGIN = 'https://float-safe-steam-test.float-cs2-lab-26.workers.dev';
const MAX_BODY = 12_000;

function reply(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  res.end(JSON.stringify(body));
}

function constantTimeMatch(received, expected) {
  const x = Buffer.from(received || '', 'utf8');
  const y = Buffer.from(expected, 'utf8');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function validateAssertion(params) {
  const required = ['openid.ns','openid.mode','openid.op_endpoint','openid.return_to','openid.claimed_id','openid.identity','openid.response_nonce','openid.assoc_handle','openid.sig','openid.signed'];
  if (required.some((key) => !params.has(key) || params.getAll(key).length !== 1)) return false;
  if (Array.from(params.keys()).some((key) => params.getAll(key).length > 1)) return false;
  const returnTo = params.get('openid.return_to');
  try {
    const u = new URL(returnTo);
    const state = u.searchParams.get('state') || '';
    if (u.origin !== CALLBACK_ORIGIN || u.pathname !== '/auth/callback' || u.searchParams.size !== 1 || state.length < 40 || state.length > 300) return false;
  } catch { return false; }
  const claimedId = params.get('openid.claimed_id');
  const identity = params.get('openid.identity');
  return params.get('openid.ns') === 'http://specs.openid.net/auth/2.0' &&
    params.get('openid.mode') === 'check_authentication' &&
    params.get('openid.op_endpoint') === STEAM_ENDPOINT &&
    identity === claimedId &&
    /^https?:\/\/steamcommunity\.com\/openid\/id\/7656119\d{10}$/.test(claimedId);
}

export function createVerifierServer({secret, fetchFn = fetch}) {
  if (typeof secret !== 'string' || secret.length < 48) throw new Error('VERIFIER_SECRET must be at least 48 characters');
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      reply(res, 200, {ok: true, app: 'float-steam-verifier'});
      return;
    }
    if (req.method !== 'POST' || req.url !== '/verify') {
      reply(res, 404, {error: 'not_found'});
      return;
    }
    if (!constantTimeMatch(req.headers.authorization, 'Bearer ' + secret)) {
      reply(res, 401, {error: 'unauthorized'});
      return;
    }
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/x-www-form-urlencoded')) {
      reply(res, 415, {error: 'unsupported_media_type'});
      return;
    }
    let raw = '';
    try {
      for await (const chunk of req) {
        raw += chunk.toString('utf8');
        if (raw.length > MAX_BODY) throw new Error('too_large');
      }
    } catch {
      reply(res, 413, {error: 'too_large'});
      return;
    }
    const params = new URLSearchParams(raw);
    if (!validateAssertion(params)) {
      reply(res, 400, {error: 'invalid_assertion'});
      return;
    }
    try {
      // Fixed destination. This server cannot be used as an arbitrary HTTP proxy.
      const remote = await fetchFn(STEAM_ENDPOINT, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'text/plain',
        },
        body: params.toString(),
        signal: AbortSignal.timeout(12_000),
        redirect: 'manual',
      });
      const responseText = (await remote.text()).slice(0, 1200);
      if (!remote.ok) {
        reply(res, 502, {error: 'steam_http_' + remote.status});
        return;
      }
      // Only an explicit Steam verification can authenticate a login.
      const valid = /^is_valid\s*:\s*true\s*$/m.test(responseText);
      reply(res, 200, {valid});
    } catch {
      reply(res, 502, {error: 'steam_connection_error'});
    }
  });
  server.requestTimeout = 18_000;
  server.headersTimeout = 20_000;
  return server;
}

if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href) {
  const secret = process.env.VERIFIER_SECRET;
  const port = Number(process.env.PORT || 10000);
  const server = createVerifierServer({secret});
  server.listen(port, '0.0.0.0', () => console.log(`FLOAT verifier on port ${port}`));
}
