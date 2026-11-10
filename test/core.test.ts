import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { registerPassportRoutes } from '../src/index.ts';
import { resolveConfig } from '../src/lib/config.ts';
import { networkAccount, seal, unseal } from '../src/lib/network-accounts.ts';
import { publicAddress, publicUrl, networkFetch } from '../src/lib/network-http.ts';
const settings = { publicUrl: 'https://passport.example', storageKey: 'test-key-of-at-least-thirty-two-characters', databaseUrl: 'postgresql://test@localhost/unused_for_unit_tests' };
process.env.MULTIPASS_PUBLIC_URL = settings.publicUrl;
process.env.MULTIPASS_STORAGE_KEY = settings.storageKey;
process.env.MULTIPASS_DATABASE_URL = settings.databaseUrl;
async function application(authenticate: Parameters<typeof registerPassportRoutes>[1]['authenticate'] = async () => null) {
  const app = Fastify({ logger: false });
  app.register(cookie); app.register(registerPassportRoutes, { ...settings, authenticate });
  await app.ready(); return app;
}
test('portable configuration requires an explicit trusted origin, encryption key and database', () => {
  const value = resolveConfig(settings); assert.equal(value.publicUrl, settings.publicUrl); assert.deepEqual(value.frameAncestors, ["'self'"]);
  for (const publicUrl of ['http://passport.example', 'https://user:pass@passport.example', 'https://passport.example/path', 'https://passport.example?x=1']) assert.throws(() => resolveConfig({ ...settings, publicUrl }));
  assert.throws(() => resolveConfig({ ...settings, storageKey: 'short' }));
  assert.throws(() => resolveConfig({ ...settings, databaseUrl: 'https://db.example' }));
  assert.throws(() => resolveConfig({ ...settings, allowedEmbedOrigins: ['https://*.example'] }));
});
test('the host cookie plugin is required; no fallback session trust is invented', async () => {
  const app = Fastify(); app.register(registerPassportRoutes, { ...settings, authenticate: async () => null });
  await assert.rejects(app.ready(), /@fastify\/cookie/); await app.close();
});
test('anonymous and browser-claimed identities cannot access private connections', async () => {
  const app = await application();
  const response = await app.inject({ url: '/v1/networks', headers: { 'x-user': 'claimed-id', authorization: 'Bearer untrusted' } });
  assert.equal(response.statusCode, 401); assert.equal(response.json().error, 'unauthenticated'); assert.equal(response.json().signInUrl, 'https://passport.example/login');
  await app.close();
});
test('invalid host principal output is rejected before any database operation', async () => {
  const app = await application(async () => ({ principalId: ' ' }));
  assert.equal((await app.inject({ url: '/v1/networks' })).statusCode, 401); await app.close();
});
test('cross-origin and missing-origin writes fail before authentication or storage', async () => {
  let calls = 0; const app = await application(async () => { calls++; return null; });
  for (const origin of [undefined, 'https://other.example', 'null']) {
    const result = await app.inject({ method: 'POST', url: '/v1/networks/save', headers: origin ? { origin } : {}, payload: { provider: 'bluesky', address: 'alice.example.social' } });
    assert.equal(result.statusCode, 403); assert.equal(result.json().error, 'network_origin');
  }
  assert.equal(calls, 0); await app.close();
});
test('public UI and OAuth metadata contain no branded host dependency or private credential', async () => {
  const app = await application();
  const metadata = await app.inject({ url: '/v1/networks/bluesky-client.json' }); assert.equal(metadata.statusCode, 200);
  const value = metadata.json(); assert.equal(value.scope, 'atproto'); assert.equal(value.token_endpoint_auth_method, 'none'); assert.equal(value.client_secret, undefined); assert.ok(value.client_id.startsWith(value.client_uri));
  const ui = await app.inject({ url: '/v1/networks/ui' }); assert.equal(ui.statusCode, 200); assert.match(ui.headers['content-security-policy']!, /frame-ancestors 'self'$/);
  assert.equal(ui.body.includes('passport.xirtus.com'), false); assert.match(ui.body, /LEELOO MULTIPASS/);
  const font = await app.inject({ url: '/v1/networks/font' }); assert.equal(font.statusCode, 200); assert.equal(font.rawPayload.subarray(0, 4).toString(), 'wOF2'); assert.match(ui.headers['content-security-policy']!, /font-src 'self'/);
  const script = await app.inject({ url: '/v1/networks/script' }); assert.equal(script.statusCode, 200); assert.equal(script.body.includes('/v1/auth/login'), false);
  await app.close();
});
test('callback never consumes a browser-supplied proof without a host session', async () => {
  const app = await application();
  const result = await app.inject({ url: '/v1/networks/callback/matrix?state=forged&loginToken=forged' });
  assert.equal(result.statusCode, 302); assert.match(result.headers.location!, /Sign%20in/); await app.close();
});
test('account parsing keeps stable network namespaces and no implicit verified flag', () => {
  assert.equal(networkAccount('bluesky', '@alice.example.social').address, 'alice.example.social');
  assert.equal(networkAccount('matrix', '@alice:matrix.example').network, 'https://matrix.example');
  assert.equal(networkAccount('mastodon', 'https://social.example/@alice').address, '@alice@social.example');
  assert.equal(networkAccount('fediverse', '@alice@threads.net').network, 'https://threads.net');
  assert.equal('verifiedAt' in networkAccount('bluesky', 'alice.example.social'), false);
});
test('state encryption detects modification and never stores plaintext credentials', () => {
  const input = { verifier: 'private-value', clientSecret: 'credential-value' }; const value = seal(input);
  assert.equal(value.includes(input.verifier), false); assert.deepEqual(unseal(value), input);
  const bytes = Buffer.from(value, 'base64url'); bytes[30] = bytes[30]! ^ 1; assert.throws(() => unseal(bytes.toString('base64url')));
});
test('outbound HTTP blocks private destinations and unsafe URL forms', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1', '::ffff:127.0.0.1']) assert.equal(publicAddress(address), false);
  assert.equal(publicAddress('8.8.8.8'), true);
  for (const address of ['http://public.example', 'https://localhost', 'https://127.0.0.1', 'https://name:secret@public.example', 'https://public.example:8443']) assert.throws(() => publicUrl(address));
  await assert.rejects(networkFetch('https://127.0.0.1/private'));
});
