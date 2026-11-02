import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { SessionClient } from './session-protocol.mjs';

const session = (generation = 1, sessionId = '11111111-1111-1111-1111-111111111111') => ({
  protocolVersion: 2, sessionId, generation, refreshToken: 'x'.repeat(43),
  accessExpiration: '2026-10-04T20:15:00Z', refreshExpiration: '2026-10-11T20:00:00Z' });
const winner = { accessToken: 'winning-access-token', session: session(2) };
function client() { const client = new SessionClient(''); client.login('original-access-token', session()); return client; }

for (const winnerFirst of [false, true]) {
  test(`winner and stale clear preserve usable credentials; winner first = ${winnerFirst}`, () => {
    const c = client(), snapshot = c.capture();
    const stale = new Headers({ AppStatus: 'CLIENT_CLEAR_ACCESS_TOKEN', 'Session-Clear-Token-Hash': snapshot.state.accessTokenHash });
    if (winnerFirst) { assert.equal(c.applyRefresh(snapshot, winner), true); assert.equal(c.applyStatus(snapshot, stale), false); }
    else { assert.equal(c.applyStatus(snapshot, stale), true); assert.equal(c.applyRefresh(snapshot, winner), true); }
    assert.equal(c.state.accessToken, winner.accessToken); assert.equal(c.state.generation, 2);
  });
}
test('late refresh cannot revive logout or overwrite replacement login', () => {
  const c = client(), snapshot = c.capture(); c.discard();
  assert.equal(c.applyRefresh(snapshot, winner), false); assert.equal(c.state, null);
  c.login('new-login', session(1, '22222222-2222-2222-2222-222222222222'));
  assert.equal(c.applyRefresh(snapshot, winner), false); assert.equal(c.state.accessToken, 'new-login');
});
test('out-of-order older success and malformed metadata cannot regress generation', () => {
  const c = client(), first = c.capture(); c.applyRefresh(first, winner);
  const second = c.capture(); assert.equal(c.applyRefresh(second, { accessToken: 'generation-three', session: session(3) }), true);
  assert.equal(c.applyRefresh(first, winner), false);
  assert.equal(c.applyRefresh(c.capture(), { accessToken: 'bad', session: session(Number.MAX_SAFE_INTEGER + 1) }), false);
  assert.equal(c.state.generation, 3);
});
test('matching access expiry retains refresh and legacy untargeted clear is ignored', () => {
  const c = client(), snapshot = c.capture();
  assert.equal(c.applyStatus(snapshot, new Headers({ AppStatus: 'CLIENT_CLEAR_ACCESS_TOKEN' })), false);
  assert.equal(c.applyStatus(snapshot, new Headers({ AppStatus: 'CLIENT_CLEAR_ACCESS_TOKEN', 'Session-Clear-Token-Hash': snapshot.state.accessTokenHash })), true);
  assert.equal(c.state.accessToken, null); assert.equal(c.state.refreshToken, session().refreshToken);
});
test('real loopback HTTP calls coalesce into one explicit refresh', async t => {
  let calls = 0;
  const server = createServer(async (request, response) => {
    calls++; let body = ''; for await (const part of request) body += part;
    assert.equal(request.url, '/account/refresh'); assert.equal(request.method, 'POST');
    assert.ok(request.headers['security-operation-key']); assert.ok(request.headers['security-operation-recovery-key']);
    assert.equal(JSON.parse(body).generation, 1);
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ success: true, code: 'SESSION_REFRESHED', data: winner }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => { server.closeAllConnections(); server.close(); });
  const c = new SessionClient(`http://127.0.0.1:${server.address().port}`); c.login('original-access-token', session());
  const operation = SessionClient.operation(), first = c.refresh(operation), second = c.refresh(operation);
  assert.equal(first, second); await first; assert.equal(calls, 1); assert.equal(c.state.generation, 2);
});
test('lost HTTP token response reconciles status without retrying POST or inventing a token', async t => {
  let effects = 0;
  const server = createServer(async (request, response) => {
    for await (const part of request) { /* drain */ }
    if (request.method === 'POST') { effects++; request.socket.destroy(); return; }
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ state: 'Committed', steps: [{ code: 'SESSION_REFRESHED', succeeded: true }] }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => { server.closeAllConnections(); server.close(); });
  const c = new SessionClient(`http://127.0.0.1:${server.address().port}`); c.login('original-access-token', session());
  const operation = SessionClient.operation(); await assert.rejects(c.refresh(operation));
  assert.equal((await c.reconcile(operation)).requiresLogin, true); assert.equal(effects, 1);
  assert.equal(c.state.generation, 1); assert.equal(c.state.accessToken, 'original-access-token');
});
