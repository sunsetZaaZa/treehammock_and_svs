-- COR06: immutable identity -> one COR04 operation. No account cascade: receipts
-- remain available to capability recovery after account deletion. Root cleanup
-- removes the replay only after the timestamped operation key is no longer valid.
CREATE TABLE authenticated_mutation_replays (
    identity_digest bytea PRIMARY KEY CHECK (octet_length(identity_digest) = 32),
    request_hmac bytea NOT NULL CHECK (octet_length(request_hmac) = 32),
    hmac_version integer NOT NULL CHECK (hmac_version > 0),
    account_id uuid NOT NULL,
    expected_account_stamp uuid NOT NULL,
    operation_id uuid NOT NULL REFERENCES security_operations(operation_id) ON DELETE CASCADE,
    owner_token uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    replay_until timestamptz NOT NULL,
    completed_at timestamptz,
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    response_code text CHECK (response_code ~ '^[A-Z0-9_]{1,96}$'),
    safe_response text CHECK (octet_length(safe_response) <= 16384),
    CHECK (replay_until <= expires_at),
    CHECK ((completed_at IS NULL AND response_status IS NULL AND response_code IS NULL AND safe_response IS NULL)
        OR (completed_at IS NOT NULL AND response_status IS NOT NULL AND response_code IS NOT NULL))
);
CREATE INDEX authenticated_mutation_replays_operation ON authenticated_mutation_replays (operation_id, identity_digest);
