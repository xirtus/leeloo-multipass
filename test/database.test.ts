import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { randomUUID } from 'node:crypto';
import { registerPassportRoutes, migrate } from '../src/index.ts';
import { query, closePool } from '../src/lib/db.ts';
import { networkAccount, saveNetwork, stateStore } from '../src/lib/network-accounts.ts';
import { instanceActor } from '../src/lib/activitypub.ts';

describe('standalone PostgreSQL schema and principal isolation', { skip: process.env.MULTIPASS_RUN_DATABASE_TESTS !== '1' }, () => {
  const a = 'host-account:' + randomUUID(), b = 'other-host-account:' + randomUUID();
  let activePrincipal = a;
  const app = Fastify({ logger: false });
  const headers = { origin: process.env.MULTIPASS_PUBLIC_URL! };
  before(async () => {
    await migrate(); assert.deepEqual(await migrate(), [], 'repeat migration is a no-op');
    app.register(cookie); app.register(registerPassportRoutes, { authenticate: async () => ({ principalId: activePrincipal }) }); await app.ready();
  });
  after(async () => { await app.close(); await closePool(); });
  test('saving registers a server-authenticated text principal, ignoring browser ownership hints', async () => {
    const response = await app.inject({ method: 'POST', url: '/v1/networks/save', headers, payload: { provider: 'bluesky', address: 'alice.example.social', principalId: b } });
    assert.equal(response.statusCode, 200, response.body);
    const principal = (await query('SELECT id FROM passport_principals WHERE id=$1', [a])).rows[0]; assert.equal(principal.id, a);
    const rows = (await app.inject({ url: '/v1/networks' })).json(); assert.equal(rows.length, 1); assert.equal(rows[0].verifiedAt, null);
  });
  test('a second authenticated principal has no access to the first principal connections', async () => {
    activePrincipal = b; assert.deepEqual((await app.inject({ url: '/v1/networks' })).json(), []);
    activePrincipal = a; const rows = (await app.inject({ url: '/v1/networks' })).json();
    activePrincipal = b; await app.inject({ method: 'POST', url: '/v1/networks/disconnect', headers, payload: { id: rows[0].id } });
    activePrincipal = a; assert.equal((await app.inject({ url: '/v1/networks' })).json().length, 1);
  });
  test('a verified subject cannot be linked to two independent host principals', async () => {
    const account = networkAccount('matrix', '@alice:matrix.example'); await saveNetwork(a, account, '@alice:matrix.example');
    await assert.rejects(saveNetwork(b, account, '@alice:matrix.example'), (error: unknown) => (error as { code: string }).code === 'network_already_linked');
  });
  test('a mutable handle updates the existing verified DID stamp', async () => {
    const first = await saveNetwork(a, networkAccount('bluesky', 'old.example.social'), 'did:plc:stable-example');
    await saveNetwork(a, networkAccount('bluesky', 'new.example.social'));
    const second = await saveNetwork(a, networkAccount('bluesky', 'new.example.social'), 'did:plc:stable-example');
    assert.equal(first!.id, second!.id);
    const rows = await query('SELECT address FROM passport_network_accounts WHERE principal_id=$1 AND subject=$2', [a, 'did:plc:stable-example']);
    assert.equal(rows.rows.length, 1); assert.equal(rows.rows[0].address, 'new.example.social');
  });
  test('encrypted state is single-use and expired state is unavailable', async () => {
    const store = stateStore<{ secret: string }>('integration:'); await store.set('one', { secret: 'not-plaintext' });
    const row = (await query('SELECT ciphertext FROM passport_network_state WHERE key=$1', ['integration:one'])).rows[0]; assert.equal(row.ciphertext.includes('not-plaintext'), false);
    assert.deepEqual(await store.consume('one'), { secret: 'not-plaintext' }); assert.equal(await store.consume('one'), undefined);
    await store.set('expired', { secret: 'old' }); await query("UPDATE passport_network_state SET expires_at=now()-interval '1 second' WHERE key=$1", ['integration:expired']); assert.equal(await store.get('expired'), undefined);
  });
  test('the signed-fetch actor uses configured origin and persisted encrypted keys', async () => {
    const actor = await instanceActor(); assert.equal(actor.id, process.env.MULTIPASS_PUBLIC_URL + '/v1/networks/actor');
    assert.match(actor.publicKey.publicKeyPem, /BEGIN PUBLIC KEY/);
    const row = (await query("SELECT ciphertext FROM passport_network_state WHERE key='activitypub-signing-key'")).rows[0]; assert.equal(row.ciphertext.includes('PRIVATE KEY'), false);
  });
  test('schema has no dependency on game, player, score or wallet tables', async () => {
    const names = (await query("SELECT tablename FROM pg_tables WHERE schemaname='public'")).rows.map(row => row.tablename);
    for (const forbidden of ['players', 'profiles', 'game_scores', 'score_events', 'inventory_items']) assert.equal(names.includes(forbidden), false);
    assert.equal(names.includes('passport_principals'), true); assert.equal(names.includes('passport_audit_events'), true);
  });
});
