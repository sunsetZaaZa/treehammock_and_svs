// Executable client contract fixture. No product client was supplied.
// The caller persists pending operation keys before sending a mutation.
import { createHash, randomBytes, randomUUID } from 'node:crypto';

const hash = token => createHash('sha256').update(token).digest('hex').toUpperCase();
const valid = session => session?.protocolVersion === 2 && typeof session.sessionId === 'string'
  && Number.isSafeInteger(session.generation) && session.generation > 0
  && /^[A-Za-z0-9_-]{43}$/.test(session.refreshToken);

export class SessionClient {
  #state = null;
  #epoch = 0;
  #refreshing = null;
  constructor(baseUrl, transport = fetch) { this.baseUrl = baseUrl; this.transport = transport; }
  get state() { return this.#state; }
  login(accessToken, session) {
    if (!accessToken || !valid(session)) throw new Error('Invalid session response');
    this.#epoch++;
    this.#state = Object.freeze({ accessToken, accessTokenHash: hash(accessToken), ...session });
  }
  discard() { this.#epoch++; this.#state = null; }
  capture() { return Object.freeze({ state: this.#state, epoch: this.#epoch }); }
  applyRefresh(snapshot, response) {
    const session = response.session;
    if (!valid(session) || !response.accessToken || snapshot.epoch !== this.#epoch || !this.#state
      || session.sessionId !== snapshot.state?.sessionId || session.sessionId !== this.#state.sessionId
      || session.generation !== snapshot.state.generation + 1
      || session.generation <= this.#state.generation) return false;
    this.#state = Object.freeze({ accessToken: response.accessToken, accessTokenHash: hash(response.accessToken), ...session });
    return true;
  }
  applyStatus(snapshot, headers) {
    // Compare with the credential actually sent. A token-clear for an older
    // request cannot delete the winner. Access expiry leaves refresh available.
    if (headers.get('AppStatus') !== 'CLIENT_CLEAR_ACCESS_TOKEN' || !this.#state
      || snapshot.epoch !== this.#epoch || snapshot.state?.accessTokenHash !== this.#state.accessTokenHash
      || headers.get('Session-Clear-Token-Hash') !== snapshot.state.accessTokenHash) return false;
    this.#state = Object.freeze({ ...this.#state, accessToken: null });
    return true;
  }
  static operation() {
    return Object.freeze({ key: `${Math.floor(Date.now() / 1000)}.${randomUUID().replaceAll('-', '')}`,
      recovery: randomBytes(32).toString('base64') });
  }
  refresh(operation) {
    // Calls share a single promise and one caller-retained identity. No automatic
    // POST retry or fresh operation is created after an uncertain outcome.
    if (this.#refreshing) return this.#refreshing;
    const snapshot = this.capture();
    if (!snapshot.state || !operation?.key || !operation?.recovery) return Promise.reject(new Error('Session and operation required'));
    const run = async () => {
      const response = await this.transport(`${this.baseUrl}/account/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json',
          'Security-Operation-Key': operation.key, 'Security-Operation-Recovery-Key': operation.recovery },
        body: JSON.stringify({ protocolVersion: 2, sessionId: snapshot.state.sessionId,
          generation: snapshot.state.generation, refreshToken: snapshot.state.refreshToken }) });
      const outcome = await response.json();
      if (!response.ok || !outcome.success || !this.applyRefresh(snapshot, outcome.data))
        throw new Error(outcome.code ?? 'REFRESH_OUTCOME_REQUIRES_RECONCILIATION');
      return this.#state;
    };
    this.#refreshing = run().finally(() => { this.#refreshing = null; });
    return this.#refreshing;
  }
  async reconcile(operation) {
    const response = await this.transport(`${this.baseUrl}/account/security-operations/status`, {
      headers: { 'Security-Operation-Key': operation.key, 'Security-Operation-Recovery-Key': operation.recovery } });
    const status = await response.json();
    // Committed refresh with lost output requires a new password/factor login.
    // Pending/Unknown stays pending. This fixture never fabricates credentials.
    return { status, requiresLogin: ['Committed', 'PartiallyCommitted'].includes(status.state)
      && status.steps?.some(step => step.code === 'SESSION_REFRESHED' && step.succeeded === true) };
  }
}
