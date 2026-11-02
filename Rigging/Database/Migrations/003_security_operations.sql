-- COR04: operation rows deliberately have no cascading account FK. Receipts
-- survive account deletion and contain no bearer credentials or proof material.
CREATE TABLE security_operations (
    operation_id uuid PRIMARY KEY,
    request_hmac bytea NOT NULL CHECK (octet_length(request_hmac) = 32),
    recovery_hmac bytea NOT NULL CHECK (octet_length(recovery_hmac) = 32),
    hmac_version integer NOT NULL CHECK (hmac_version > 0),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 256),
    account_id uuid,
    issued_at timestamptz NOT NULL,
    execute_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'Pending'
        CHECK (state IN ('Pending', 'Committed', 'RolledBack', 'PartiallyCommitted')),
    http_status integer CHECK (http_status BETWEEN 100 AND 599),
    finished_at timestamptz,
    CHECK (issued_at < expires_at AND execute_before < expires_at)
);
CREATE INDEX security_operations_expiry ON security_operations (expires_at, operation_id);
CREATE TABLE security_operation_steps (
    operation_id uuid NOT NULL REFERENCES security_operations(operation_id) ON DELETE CASCADE,
    step_key text NOT NULL CHECK (length(step_key) BETWEEN 1 AND 256),
    request_hmac bytea NOT NULL CHECK (octet_length(request_hmac) = 32),
    expected_account_stamp uuid,
    expected_version text,
    outcome_code text NOT NULL CHECK (outcome_code ~ '^[A-Z0-9_]{1,96}$'),
    succeeded boolean,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation_id, step_key)
);
-- All participants lock the operation gate before account/domain rows. The
-- gate is held in the *same* transaction as the domain mutation and step insert.
create or replace function lock_security_operation(p_id uuid, p_account uuid)
returns void
language plpgsql
as $$
DECLARE r security_operations%ROWTYPE;
BEGIN
    SELECT * INTO r FROM security_operations WHERE operation_id = p_id FOR UPDATE;
    IF NOT FOUND OR r.state <> 'Pending' OR r.execute_before <= clock_timestamp()
        OR r.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'Security operation fenced' USING ERRCODE = 'P0404';
    END IF;
    IF r.account_id IS NOT NULL AND p_account IS NOT NULL AND r.account_id <> p_account THEN
        RAISE EXCEPTION 'Security operation scope mismatch' USING ERRCODE = 'P0405';
    END IF;
    UPDATE security_operations SET account_id = coalesce(account_id, p_account) WHERE operation_id = p_id;
end;
$$;
-- Expired admission is terminally fenced while holding the same gate as every
-- mutation. Missing rows are Unknown, never evidence of rollback. NOWAIT
-- callers return Pending for an observed gate holder rather than hanging.
create or replace function reconcile_security_operation(p_id uuid)
returns text
language plpgsql
as $$
DECLARE r security_operations%ROWTYPE; terminal text;
BEGIN
    SELECT * INTO r FROM security_operations WHERE operation_id = p_id FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RETURN 'Unknown'; END IF;
    IF r.expires_at <= clock_timestamp() THEN RETURN 'Expired'; END IF;
    IF r.state = 'Pending' AND r.execute_before <= clock_timestamp() THEN
        terminal := CASE WHEN EXISTS(SELECT 1 FROM security_operation_steps WHERE operation_id = p_id)
            THEN 'PartiallyCommitted' ELSE 'RolledBack' END;
        UPDATE security_operations SET state = terminal, finished_at = clock_timestamp() WHERE operation_id = p_id;
        RETURN terminal;
    END IF;
    RETURN r.state;
EXCEPTION WHEN lock_not_available THEN RETURN 'Pending';
end;
$$;
-- An immutable key includes its issued-at timestamp; admission rejects expired
-- keys before INSERT, even after these rows have been removed. Bounded cleanup
-- locks only operation gates; it never acquires account/child domain locks.
create or replace function purge_security_operations(p_limit integer DEFAULT 100)
returns integer
language plpgsql
as $$
DECLARE removed integer;
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN RAISE EXCEPTION 'Invalid cleanup batch'; END IF;
    WITH batch AS (
        SELECT operation_id FROM security_operations WHERE expires_at < clock_timestamp() - interval '2 minutes'
        ORDER BY expires_at, operation_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM security_operations s USING batch b WHERE s.operation_id = b.operation_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
end;
$$;
