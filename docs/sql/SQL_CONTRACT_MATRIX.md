# Current canonical SQL source index — COR23

Generated from the current pre-1.0 canonical setup. All 176 function declarations are indexed. This replaces the stale 89-function matrix. Declarations and lexical C# references are source metadata, not executable parameter/reader contracts or measured plans. Zero lexical references can mean SQL-internal use, dynamic calls or a legacy denied surface; it does not prove unused code. PostgreSQL catalog parity, every actual repository result reader, supported branch execution, account-first lock graph, exact expiry and measured query plans remain native qualification obligations. Frozen R06 and scoped COR23A/B/C evidence remain open. The generated baselines/checksummed setup remain authoritative.

## cor02_lock_account_authority

```sql
create or replace function cor02_lock_account_authority(p_id uuid, p_scope text) returns boolean language plpgsql
```

Source line: 383. Definition SHA256: `c93614d1b70db82918d463dede43db58c5d7a2810aa9c860698331128a9ef764`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor02_require_live

```sql
create or replace function cor02_require_live(p_expiration timestamp with time zone) returns void language plpgsql
```

Source line: 420. Definition SHA256: `8f6da2a5392e3afb11c545f53c1340c40a714b704bdce4ecb737ab9a4e9af977`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor02_expiration_is_live

```sql
create or replace function cor02_expiration_is_live(p_expiration timestamp with time zone, p_authority timestamp with time zone) returns boolean language sql immutable
```

Source line: 429. Definition SHA256: `84c5fe23e9bab9e7f050f29ff881e20e1e864d2456ed0250a1ff50cb8d4cf1bb`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## lock_security_operation

```sql
create or replace function lock_security_operation(p_id uuid, p_account uuid) returns void language plpgsql
```

Source line: 434. Definition SHA256: `d9ea2ec2735eed8422b4c1768856f6733c37e5fa7d9bb1849033894cfcd81e78`.

Lexical C# references: `Repos/AuthenticatedMutationReplayRepo.cs`, `Services/SecurityOperationService.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## reconcile_security_operation

```sql
create or replace function reconcile_security_operation(p_id uuid) returns text language plpgsql
```

Source line: 452. Definition SHA256: `b53c07f4dd3aa76e9ee2fdb7cb5a27183effe4083e8ce72d850005db208f5e19`.

Lexical C# references: `Repos/SecurityOperationRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## purge_security_operations

```sql
create or replace function purge_security_operations(p_limit integer DEFAULT 100) returns integer language plpgsql
```

Source line: 472. Definition SHA256: `afc99ce77cacf26487ba0c19c658d117155bcfa1160e6e2f16a2224be424e8e6`.

Lexical C# references: `Repos/SecurityOperationRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## upgrade_account_password_hash

```sql
create or replace function upgrade_account_password_hash( p_account uuid, p_stamp uuid, p_old_hash bytea, p_new_hash bytea) returns boolean language plpgsql
```

Source line: 488. Definition SHA256: `5d8eea9218b12cc77c449523bbb5e4309edd41a70f147f7506e2cac1883d1011`.

Lexical C# references: `Repos/AccountRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_record_login_failure

```sql
create or replace function cor08_record_login_failure(p_account uuid, p_stamp uuid, p_charge integer, p_limit integer) returns table(result boolean, code text, failures smallint, unlock_when timestamptz, attempt_version uuid) language plpgsql
```

Source line: 504. Definition SHA256: `369a26bc20f34b8eb7e640766a1483ad954de49c450d8dfb91f460344d16d1ed`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_clear_login_attempts

```sql
create or replace function cor08_clear_login_attempts(p_account uuid, p_stamp uuid, p_version uuid, p_failures smallint, p_unlock timestamptz, p_expired_cleanup boolean) returns table(result boolean, code text, failures smallint, unlock_when timestamptz, attempt_version uuid) language plpgsql
```

Source line: 529. Definition SHA256: `be91d99cd49b3eb918a034f095d5f220815b9d23bc2c69562e42e144956cedeb`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_factor_policy

```sql
create or replace function cor08_factor_policy(p_account uuid) returns text language sql stable
```

Source line: 555. Definition SHA256: `da788ee6ba4ef1c70c26b036651e051db493452d797a2b3178e3466a4a183121`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_live_sensitive_authority

```sql
create or replace function cor08_live_sensitive_authority(p_account uuid,p_stamp uuid,p_session text,p_family uuid) returns boolean language sql volatile
```

Source line: 566. Definition SHA256: `816d019108a7332940aaf8eb922847b4e77a6a30ad790451255106e2d8ba8c23`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_begin_password_proof

```sql
create or replace function cor08_begin_password_proof(p_account uuid,p_stamp uuid,p_session text,p_attempt uuid, p_purpose smallint,p_target text,p_limit integer,p_window integer,p_lease integer) returns table(result boolean,code text,hashed_password bytea,factor_required boolean) language plpgsql
```

Source line: 580. Definition SHA256: `075bed9a1a5b3d8eeb1a30c7ada7521b9cac86c4ae8cec0bfcb4f48192f3a95a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_abandon_password_proof

```sql
create or replace function cor08_abandon_password_proof(p_account uuid,p_stamp uuid,p_attempt uuid) returns boolean language plpgsql
```

Source line: 619. Definition SHA256: `3f89f0a4a0e381426def20e15813f29c07f4a2025581c183a6a25fbad1ba36bc`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_finish_password_proof

```sql
create or replace function cor08_finish_password_proof(p_account uuid,p_stamp uuid,p_session text,p_attempt uuid,p_verified boolean, p_handle text,p_token text,p_minutes integer) returns table(result boolean,code text,expiration timestamptz,factor_required boolean) language plpgsql
```

Source line: 635. Definition SHA256: `9530d83e7a39e87147f01a70b2c02a3e3910329e21fd5ae029088c1c0d6f338c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_reserve_factor_proof

```sql
create or replace function cor08_reserve_factor_proof(p_account uuid,p_stamp uuid,p_session text,p_handle text,p_limit integer) returns boolean language plpgsql
```

Source line: 669. Definition SHA256: `c6954b9bd7213931a0a6fca43ca31ef558999683c63bce8603e8005ef4065634`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_finish_factor_proof

```sql
create or replace function cor08_finish_factor_proof(p_account uuid,p_stamp uuid,p_session text,p_handle text,p_token text) returns table(result boolean,code text,expiration timestamptz,factor_required boolean) language plpgsql
```

Source line: 686. Definition SHA256: `d07630e39ed9bfd947a3738a97ded4c292d2fd3d6d857200afa13924f28a8124`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_validate_sensitive_grant

```sql
create or replace function cor08_validate_sensitive_grant(p_account uuid,p_stamp uuid,p_session text,p_token text, p_purpose smallint,p_target text,p_consume boolean) returns boolean language plpgsql
```

Source line: 705. Definition SHA256: `a3bf2bfeb4621fec4cc1f279686f178cfebb51d96b191aa551b3296a190efdcc`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_authorized_begin_authenticator_app_setup

```sql
create or replace function cor08_authorized_begin_authenticator_app_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text, p_createdOn timestamp with time zone, p_expiration timestamp with time zone, p_authId text, p_required boolean, p_totpProviderType smallint, p_totpSecretCiphertext bytea, p_totpSecretNonce bytea, p_totpSecretTag bytea, p_totpSecretVersion integer, p_totpKeyId text, p_totpEnrollmentId uuid, p_totpAlgorithm text, p_totpDigits integer, p_totpPeriodSeconds integer, p_totpClockSkewSteps integer,p_expectedRequestId uuid,p_expectedVersion bigint, p_grant_session text,p_grant_token text,p_grant_target text) returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone) language plpgsql
```

Source line: 725. Definition SHA256: `fa9e66dc598e1ebda72c68bbf4da2e5d103a483595621e8eeac0010daaa70f23`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor08_authorized_remove_twofactor_method

```sql
create or replace function cor08_authorized_remove_twofactor_method( p_accountId uuid, p_accountSecurityStamp uuid, p_method smallint, p_now timestamp with time zone, p_grant_session text,p_grant_token text,p_grant_target text) returns table( result boolean, code text, removed_method smallint, two_factor_methods smallint[], available_configurations smallint[]) language plpgsql
```

Source line: 805. Definition SHA256: `940dca86b195f2a321db5bcfaa19f508d954b89d21828b368857207b9d1e5f28`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor15_enrollment_contract

```sql
create or replace function cor15_enrollment_contract() returns trigger language plpgsql
```

Source line: 1005. Definition SHA256: `c79496696794677bafa90c8d22f9149aa4a421055fd054a849ce8b7ae0c02946`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23i_attempt_identity

```sql
create or replace function cor23i_attempt_identity() returns trigger language plpgsql
```

Source line: 1169. Definition SHA256: `f92ed8f2e4d7b04dabb9f01ff4e8dd06adcaa43f35bd64be4b6d691e26c5cec8`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## resolve_available_twofactor_configurations

```sql
create or replace function resolve_available_twofactor_configurations(p_accountId uuid) returns smallint[] language sql volatile
```

Source line: 1187. Definition SHA256: `db2dc99a0bb32e4698cc7b316a1a99adfc51068cafdb3c21412b44c84fb010d9`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## setup_account_email

```sql
create or replace function setup_account_email( p_accountId uuid, p_emailAddress text, p_webKey text, p_hashedPassword bytea, p_saltOne bytea, p_siv bytea, p_nonce bytea, p_country smallint, p_verifyKeyHash text, p_createdOn timestamp with time zone, p_verificationExpiration interval) returns table(verification_index bigint, outcome smallint) language plpgsql
```

Source line: 1566. Definition SHA256: `64ce18b5db63e8ae681bc5a2e35e2060df578727a3d79da0c65310d1f5bb6a01`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## setup_account_both

```sql
create or replace function setup_account_both( p_accountId uuid, p_username text, p_emailAddress text, p_webKey text, p_hashedPassword bytea, p_saltOne bytea, p_siv bytea, p_nonce bytea, p_country smallint, p_verifyKeyHash text, p_createdOn timestamp with time zone, p_verificationExpiration interval) returns table(verification_index bigint, outcome smallint) language plpgsql
```

Source line: 1634. Definition SHA256: `6006471d7dc95e6c6cfa845494e8e091aa7758746b740372a4f05b470476ad33`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## start_verify_account

```sql
create or replace function start_verify_account( p_accountGuid uuid, p_verificationIndex bigint) returns table(result boolean) language plpgsql
```

Source line: 1723. Definition SHA256: `8568e83b54809e7bad0e0359aaa8680fb6009f275548c729c83c1c30108992ca`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## resend_verify_account

```sql
create or replace function resend_verify_account( p_emailAddress text, p_verifyKeyHash text, p_verificationExpiration interval) returns table(result boolean, code text, email_address text) language plpgsql
```

Source line: 1753. Definition SHA256: `bfe916e8902bc84577b81c337ab224e4d160bcc1394ace6bc5427f2f85242585`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## verify_account_for_use

```sql
create or replace function verify_account_for_use(p_verifyKeyHash text) returns table( account_id uuid, verify_key_hash text, verify_status smallint, sent_when timestamp with time zone, expiration interval, proof_version uuid, account_security_stamp uuid) language sql stable
```

Source line: 1808. Definition SHA256: `7f5bbd3b71b6048ac98a0c84a69f0deb344f9f1f32e9737007c1268eee065d31`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## complete_verify_account

```sql
create or replace function complete_verify_account( p_accountId uuid, p_verifyKeyHash text, p_proofVersion uuid, p_accountSecurityStamp uuid) returns table(result boolean) language plpgsql
```

Source line: 1832. Definition SHA256: `c463b98a84fa560b252abf596fcf65fa10a07dbf48e897f8c9c084f31c384956`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## expire_verify_account

```sql
create or replace function expire_verify_account( p_accountId uuid, p_verifyKeyHash text, p_proofVersion uuid, p_accountSecurityStamp uuid) returns table(result boolean) language plpgsql
```

Source line: 1870. Definition SHA256: `daf212c67b8d7dc8b5a9ba424b247c9400b046a1534d126a4f72539f1d9a7d5d`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_session

```sql
create or replace function get_session(p_accessTokenHash text) returns table( account_id uuid, refresh_token bytea, refreshes smallint, refresh_limit smallint, created_on timestamp with time zone, session_lifespan interval, access_expiration timestamp with time zone, session_expiration timestamp with time zone, cut_off timestamp with time zone, features smallint, security_stamp uuid, account_security_stamp uuid, session_id uuid, generation bigint, protocol_version integer, entitlement_json text) language plpgsql volatile
```

Source line: 1906. Definition SHA256: `e657ca8cb88ab0dcdf1e88fe5027b1a11670b092171b682a870e0a6a5c68b70c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_current_active_session_hash

```sql
create or replace function get_current_active_session_hash( p_accountId uuid) returns table(active_access_token_hash text) language sql stable
```

Source line: 1957. Definition SHA256: `b12528c12b6bb4c5691de862806c3620b2db91e57b40fb4b90f073c2c4dd600a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## check_account_emailaddress_creds

```sql
create or replace function check_account_emailaddress_creds(p_emailAddress text) returns table( account_id uuid, hashed_password bytea, web_key text, refresh_token bytea, refreshes smallint, refresh_limit smallint, created_on timestamp with time zone, lifespan interval, salt_one bytea, siv bytea, nonce bytea, unlock_when timestamp with time zone, login_failures smallint, verify_status smallint, features smallint, two_factor_access_token text, two_factor_auth_method smallint, two_auth_usage smallint, cut_off timestamp with time zone, account_security_stamp uuid, active_access_token_hash text,entitlement_json text) language plpgsql volatile
```

Source line: 1975. Definition SHA256: `cf0a168b69a917c0c981577eb175c6e074448ace6b11ceaec7c09dbfb9773046`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## check_account_username_creds

```sql
create or replace function check_account_username_creds(p_username text) returns table( account_id uuid, hashed_password bytea, web_key text, refresh_token bytea, refreshes smallint, refresh_limit smallint, created_on timestamp with time zone, lifespan interval, salt_one bytea, siv bytea, nonce bytea, unlock_when timestamp with time zone, login_failures smallint, verify_status smallint, features smallint, two_factor_access_token text, two_factor_auth_method smallint, two_auth_usage smallint, cut_off timestamp with time zone, account_security_stamp uuid, active_access_token_hash text, entitlement_json text) language plpgsql volatile
```

Source line: 2056. Definition SHA256: `643bb2706a84a7fe8dd864af21a49ec6a67c42a545a5216f9c199cb30568491e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## check_account_both_creds

```sql
create or replace function check_account_both_creds(p_username text, p_emailAddress text) returns table( account_id uuid, hashed_password bytea, web_key text, refresh_token bytea, refreshes smallint, refresh_limit smallint, created_on timestamp with time zone, lifespan interval, salt_one bytea, siv bytea, nonce bytea, unlock_when timestamp with time zone, login_failures smallint, verify_status smallint, features smallint, two_factor_access_token text, two_factor_auth_method smallint, two_auth_usage smallint, cut_off timestamp with time zone, account_security_stamp uuid, active_access_token_hash text,entitlement_json text) language plpgsql volatile
```

Source line: 2138. Definition SHA256: `2ec4db1833632e52b89710bd4c91fbf7c6d755d2bc5a5d8e1b4a057ec406ca3b`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_account_reauthentication_credentials

```sql
create or replace function get_account_reauthentication_credentials( p_accountId uuid, p_accountSecurityStamp uuid) returns table( result boolean, code text, hashed_password bytea, verify_status smallint, cut_off timestamp with time zone, account_security_stamp uuid) language sql stable
```

Source line: 2221. Definition SHA256: `ee35a0b6c74ab3c22a55cd68580cd8ac0c91dad029e8cc44b0116cf636404ca8`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## issue_sensitive_action_token

```sql
create or replace function issue_sensitive_action_token( p_accountId uuid, p_accountSecurityStamp uuid, p_sessionBindingHash text, p_tokenHash text, p_purpose smallint, p_createdOn timestamp with time zone, p_expiration timestamp with time zone, p_consumeExistingTokens boolean) returns table(result boolean, code text, token_id uuid, expiration timestamp with time zone) language plpgsql
```

Source line: 2246. Definition SHA256: `7401369877ffe21ee6177bd85bc1f49ba0e29adaa01317032bd0908d16d5988d`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## validate_sensitive_action_token

```sql
create or replace function validate_sensitive_action_token( p_accountId uuid, p_accountSecurityStamp uuid, p_sessionBindingHash text, p_tokenHash text, p_purpose smallint, p_consume boolean, p_moment timestamp with time zone) returns table(result boolean, code text, expiration timestamp with time zone) language plpgsql
```

Source line: 2263. Definition SHA256: `984f34b3261776c994638115371ebd72472051ebe557ac7df789bd36d8d13240`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## set_session

```sql
create or replace function set_session( p_accessTokenHash text, p_accountId uuid, p_refreshToken bytea, p_refreshes smallint, p_refreshLimit smallint, p_createdOn timestamp with time zone, p_sessionLifespan interval, p_accessExpiration timestamp with time zone, p_sessionExpiration timestamp with time zone, p_cutOff timestamp with time zone, p_features smallint, p_securityStamp uuid, p_accountSecurityStamp uuid) returns table(result smallint, code text) language plpgsql
```

Source line: 2279. Definition SHA256: `844f9cfa314f53b226b6412e25a95748e107ccf8b47aba408708af3a3aed9f33`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## set_account_lockout

```sql
create or replace function set_account_lockout(p_accountGuid uuid, p_expiration interval) returns table(result boolean, code text) language plpgsql
```

Source line: 2391. Definition SHA256: `ef65f16cdf71a74eb8822010b1cdd018a6d963efad9fdfaffc987988f1728d67`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## remove_account_lockout

```sql
create or replace function remove_account_lockout(p_accountGuid uuid) returns table(result boolean, code text) language plpgsql
```

Source line: 2400. Definition SHA256: `269b94d78aec56004821976781e0abd9cb9213123644d438b3bd95c4da232c1a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## set_account_login_failures

```sql
create or replace function set_account_login_failures(p_accountGuid uuid, p_failures smallint) returns table(result boolean, code text) language plpgsql
```

Source line: 2409. Definition SHA256: `2059e7da687507799479279054b31110ddb68507be08d1d0f4688128fea91abe`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## successful_login

```sql
create or replace function successful_login( p_accountId uuid, p_accountSecurityStamp uuid) returns table(result boolean, code text) language plpgsql
```

Source line: 2418. Definition SHA256: `c21999ecdc5909bbafe3e5a66b5412c35e710dbe0a80aa7cade3283f8878230f`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## rotate_account_security_stamp

```sql
create or replace function rotate_account_security_stamp(p_accountId uuid) returns table(result boolean, code text, account_security_stamp uuid) language plpgsql
```

Source line: 2430. Definition SHA256: `3e46399dcb833620ea77da5d09fee699b1ce69ed0b00142176ab83b8d98ea46c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## edit_account_username

```sql
create or replace function edit_account_username( p_accountId uuid, p_accountSecurityStamp uuid, p_username text) returns table(result boolean, code text) language plpgsql
```

Source line: 2466. Definition SHA256: `0df31436ddb9b23d38cba2a89d822a109d16062ac34681de192cc0429ae1e1f1`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## request_account_email_change

```sql
create or replace function request_account_email_change(p_accountId uuid,p_accountSecurityStamp uuid,p_newEmailAddress text,p_verifyKeyHash text,p_expiration timestamptz) returns table(result boolean,code text,email_address text) language plpgsql
```

Source line: 2524. Definition SHA256: `de0f3ec7da0b41dd8839fcd988f137b5ba9f9e807f2cd75bb441412824d91ce8`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_account_email_change_request

```sql
create or replace function cancel_account_email_change_request( p_accountId uuid, p_accountSecurityStamp uuid, p_verifyKeyHash text) returns table(result boolean, code text, email_address text) language plpgsql
```

Source line: 2529. Definition SHA256: `07b93bfdbf9eab5d2ac4640cbe5e6c64bfcd4a3ce6f2c6e823e75098c02ff4f7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## complete_account_email_change

```sql
create or replace function complete_account_email_change(p_verifyKeyHash text) returns table(result boolean,code text,account_security_stamp uuid) language plpgsql
```

Source line: 2579. Definition SHA256: `ec2be4f0c148e50d19cbd148edfa2322288eda6844f6bdb75940190d6ca5439e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## purge_expired_account_email_change_requests

```sql
create or replace function purge_expired_account_email_change_requests(p_now timestamptz default now()) returns table(result boolean,code text,deleted_count integer) language plpgsql
```

Source line: 2641. Definition SHA256: `6f1b5a35691a55923caa927c4ef075d688699653bcb6d45f10d90ceed528eda4`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## request_account_delete

```sql
create or replace function request_account_delete(p_accountId uuid,p_accountSecurityStamp uuid,p_passPhraseHash text,p_deleteTokenHash text,p_expiration timestamptz,p_requestCooldown interval,p_requestWindow interval,p_maxRequestsPerWindow smallint) returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql
```

Source line: 2647. Definition SHA256: `ad12dac23f717efe94d31cefafd934630da9bc77bda3d6d65c4ed61e77a6a293`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_account_delete_request

```sql
create or replace function cancel_account_delete_request(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text) returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql
```

Source line: 2652. Definition SHA256: `527aae92929fa401c91fad734f073593098a025dfaee7240b873274be0196cbe`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## prepare_account_delete_finalize

```sql
create or replace function prepare_account_delete_finalize(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text,p_maxFailedFinalizeAttempts smallint,p_finalizeLockout interval,p_sessionHash text) returns table(result boolean,code text,account_id uuid,workflow smallint,pass_phrase_hash text,request_id uuid) language plpgsql
```

Source line: 2667. Definition SHA256: `1e256461b25d94222c2c01e676255fbf8005139f12107307fa544d48a959044c`.

Lexical C# references: `Repos/AccountRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## commit_account_delete_finalize

```sql
create or replace function commit_account_delete_finalize(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text,p_passPhraseSatisfied boolean,p_maxFailedFinalizeAttempts smallint,p_finalizeLockout interval,p_requestId uuid,p_expectedPassPhraseHash text,p_sessionHash text) returns table(result boolean,code text,account_id uuid) language plpgsql
```

Source line: 2680. Definition SHA256: `f1c701b3a2f22840be2a7f14ec96946720f1b772b536b6e26efeb1e6f2b8cf38`.

Lexical C# references: `Repos/AccountRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## rotate_active_session

```sql
create or replace function rotate_active_session( p_accountId uuid, p_expectedOldAccessTokenHash text, p_newAccessTokenHash text, p_refreshToken bytea, p_refreshes smallint, p_refreshLimit smallint, p_createdOn timestamp with time zone, p_sessionLifespan interval, p_accessExpiration timestamp with time zone, p_sessionExpiration timestamp with time zone, p_cutOff timestamp with time zone, p_features smallint, p_securityStamp uuid, p_accountSecurityStamp uuid) returns table(status smallint, code text) language plpgsql
```

Source line: 2713. Definition SHA256: `439d474e988c57981ca72f49e5604b1045a66ff8b5e993cc3849907595accd28`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## promote_twofactor_new_login

```sql
create or replace function promote_twofactor_new_login( p_accountId uuid, p_expectedTwoFactorAccessToken text, p_accountSecurityStamp uuid, p_newAccessTokenHash text, p_refreshToken bytea, p_refreshes smallint, p_refreshLimit smallint, p_createdOn timestamp with time zone, p_sessionLifespan interval, p_accessExpiration timestamp with time zone, p_sessionExpiration timestamp with time zone, p_cutOff timestamp with time zone, p_features smallint, p_securityStamp uuid, p_expectedProofVersion bigint) returns table(result boolean, code text) language plpgsql
```

Source line: 2854. Definition SHA256: `dc099b5fd255c48a9a9456b78bbbb4904547a19fd0a609ff6a29d88ab69372ab`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## promote_twofactor_rotation_login

```sql
create or replace function promote_twofactor_rotation_login( p_accountId uuid, p_expectedTwoFactorAccessToken text, p_accountSecurityStamp uuid, p_expectedOldAccessTokenHash text, p_newAccessTokenHash text, p_refreshToken bytea, p_refreshes smallint, p_refreshLimit smallint, p_createdOn timestamp with time zone, p_sessionLifespan interval, p_accessExpiration timestamp with time zone, p_sessionExpiration timestamp with time zone, p_cutOff timestamp with time zone, p_features smallint, p_securityStamp uuid, p_expectedProofVersion bigint) returns table(result boolean, code text) language plpgsql
```

Source line: 3011. Definition SHA256: `b31c9930c1a4a6d6f075ab4b462719f4b619826e43c9ef0c499a230f0bcfd9d5`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## validate_cached_session_trust

```sql
create or replace function validate_cached_session_trust( p_accessTokenHash text, p_accountId uuid, p_securityStamp uuid, p_accountSecurityStamp uuid) returns table( status smallint, code text, access_expiration timestamp with time zone, session_expiration timestamp with time zone, cut_off timestamp with time zone, security_stamp uuid, account_security_stamp uuid, session_id uuid, generation bigint, protocol_version integer, entitlement_json text) language plpgsql volatile
```

Source line: 3205. Definition SHA256: `b53403a47fbad56026d8265d9f6c730a647c31769e8a2c4c29cbd52a453b7dbf`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## expire_session

```sql
create or replace function expire_session(p_accessTokenHash text, p_newExpiration timestamp with time zone) returns table(result boolean, code text) language plpgsql
```

Source line: 3247. Definition SHA256: `2c87e9fa0d905b23e3738effe3f3878fe46008c3aa0de5168d73b86a9243cf76`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## revoke_session

```sql
create or replace function revoke_session(p_accessTokenHash text) returns table(result boolean, code text) language plpgsql
```

Source line: 3263. Definition SHA256: `04135932c047a282bbb2e55656aa55815d934ff659c1bb5d361416962f48ccfe`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## logout_current_session

```sql
create or replace function logout_current_session( p_accountId uuid, p_accessTokenHash text, p_accountSecurityStamp uuid, p_reason text default 'current-session-logoff') returns table(result boolean, code text) language plpgsql
```

Source line: 3279. Definition SHA256: `f938d8524268b7d74f8eef793777b400c9e1a2b56664415ee9ec2878ac31e4e2`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## logout_all_sessions

```sql
create or replace function logout_all_sessions( p_accountId uuid, p_accountSecurityStamp uuid, p_reason text default 'logout-all') returns table(result boolean, code text, account_security_stamp uuid) language plpgsql
```

Source line: 3309. Definition SHA256: `7837f10955f3c81ea42d71749bc6c21ae7bf6b30c10f1a4abcc24616f9cedef8`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## list_active_sessions

```sql
create or replace function list_active_sessions( p_accountId uuid, p_accountSecurityStamp uuid, p_currentAccessTokenHash text) returns table( session_id uuid, created_on timestamp with time zone, access_expiration timestamp with time zone, session_expiration timestamp with time zone, features smallint, is_current boolean, entitlement_json text) language plpgsql volatile
```

Source line: 3370. Definition SHA256: `924957ff551da33b73c2806866d396348230155318780ffe34366ff973a484f0`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## revoke_session_for_account

```sql
create or replace function revoke_session_for_account( p_accountId uuid, p_targetSessionId uuid, p_accountSecurityStamp uuid, p_currentAccessTokenHash text) returns table(result boolean, code text) language plpgsql
```

Source line: 3419. Definition SHA256: `9a908efa691e42a6bcaaf3cce8e43af7e26e458c93bea7e9f9655fb5dfeb13ec`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_twofactor_details

```sql
create or replace function get_twofactor_details(p_accountId uuid) returns table( method smallint, auth_id text, phone_number text, phone_country_code text, email_address text) language sql stable
```

Source line: 3514. Definition SHA256: `1399fd02bf45027258c834033264f55b912bd99499f9608e3f905d0a32fa0430`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## begin_twofactor_setup

```sql
create or replace function begin_twofactor_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_method smallint, p_tokenHash text, p_createdOn timestamp with time zone, p_expiration timestamp with time zone, p_emailAddress text, p_phoneNumber text, p_phoneCountryCode text, p_authId text, p_required boolean) returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone) language plpgsql
```

Source line: 3553. Definition SHA256: `e7744e8bc0bbaf95173e4363f48fe16c02d3e251c872d7c3b21f5140307a505d`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_twofactor_setup

```sql
create or replace function cancel_twofactor_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_method smallint, p_tokenHash text) returns table(result boolean, code text) language plpgsql
```

Source line: 3573. Definition SHA256: `6714799504dc9641f555b37d6e54466296a9eff59769864ef93010274c9b79d9`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## verify_twofactor_setup

```sql
create or replace function verify_twofactor_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_method smallint, p_tokenHash text, p_maxAttempts integer, p_now timestamp with time zone,p_requestId uuid,p_requestVersion bigint,p_familyId uuid) returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone) language plpgsql
```

Source line: 3618. Definition SHA256: `d2d6278b0a3004c16b9b0d8b5f79f56d3a7be4b977d1b71df22a6bbc410c83a9`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## remove_twofactor_method

```sql
create or replace function remove_twofactor_method( p_accountId uuid, p_accountSecurityStamp uuid, p_method smallint, p_now timestamp with time zone default now()) returns table( result boolean, code text, removed_method smallint, two_factor_methods smallint[], available_configurations smallint[]) language plpgsql
```

Source line: 3670. Definition SHA256: `aeb93ae6e34ef0b4d490b3a547fdde7514b49807cd55eaf7dc632d38c978cd7c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## begin_authenticator_app_setup

```sql
create or replace function begin_authenticator_app_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text, p_createdOn timestamp with time zone, p_expiration timestamp with time zone, p_authId text, p_required boolean, p_totpProviderType smallint, p_totpSecretCiphertext bytea, p_totpSecretNonce bytea, p_totpSecretTag bytea, p_totpSecretVersion integer, p_totpKeyId text, p_totpEnrollmentId uuid, p_totpAlgorithm text, p_totpDigits integer, p_totpPeriodSeconds integer, p_totpClockSkewSteps integer,p_expectedRequestId uuid,p_expectedVersion bigint) returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone) language plpgsql
```

Source line: 3689. Definition SHA256: `94f097f6eba3678fc3b71693172cacb5f92e58c6476a1da9d17ce13cd7a91adc`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_pending_authenticator_app_setup

```sql
create or replace function get_pending_authenticator_app_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text, p_now timestamp with time zone) returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone, setup_attempts smallint, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_provider_type smallint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint) language plpgsql stable
```

Source line: 3711. Definition SHA256: `1a921a8b547016a1c5426ff738751c70e6a86e6700cb70d816d312b28cbaaf0f`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## record_authenticator_app_setup_failure

```sql
create or replace function record_authenticator_app_setup_failure( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text, p_maxAttempts smallint, p_now timestamp with time zone) returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone) language plpgsql
```

Source line: 3730. Definition SHA256: `914417f3ba5828b7466dfb718bc244da892a9dbd2ae768b96fcb653bb9eb7a2c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## complete_authenticator_app_setup_and_rotate_session

```sql
create or replace function complete_authenticator_app_setup_and_rotate_session( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text, p_timeStep bigint, p_expectedOldAccessTokenHash text, p_newAccessTokenHash text, p_refreshToken bytea, p_refreshes smallint, p_refreshLimit smallint, p_createdOn timestamp with time zone, p_sessionLifespan interval, p_accessExpiration timestamp with time zone, p_sessionExpiration timestamp with time zone, p_cutOff timestamp with time zone, p_features smallint, p_sessionSecurityStamp uuid) returns table(result boolean, code text, account_security_stamp uuid, two_factor_index bigint) language plpgsql
```

Source line: 3775. Definition SHA256: `be1552502215bb039403b9321a130549c7baef955e41055cd7d943033bda02eb`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_authenticator_app_setup

```sql
create or replace function cancel_authenticator_app_setup( p_accountId uuid, p_accountSecurityStamp uuid, p_setupTokenHash text) returns table(result boolean, code text) language plpgsql
```

Source line: 3878. Definition SHA256: `4ec294df0b2b8f9ecb377afc09bc162a6aa8322d0e44a5ee98bdb1e7f9da14d0`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_verified_totp_enrollment_for_account

```sql
create or replace function get_verified_totp_enrollment_for_account( p_accountId uuid, p_now timestamp with time zone) returns table(account_id uuid, two_factor_index bigint, method smallint, totp_provider_type smallint, totp_provider_enrollment_id text, totp_provider_account_binding_hash text, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint) language sql stable
```

Source line: 3898. Definition SHA256: `c8e2906ac67c7ee8a6f3c871af5d5b44ec22df1acf65964d7e22beaeaf772b7b`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## mark_totp_step_used

```sql
create or replace function mark_totp_step_used( p_accountId uuid, p_twoFactorIndex bigint, p_timeStep bigint, p_enrollmentId uuid) returns table(result boolean, code text) language plpgsql
```

Source line: 3917. Definition SHA256: `ec3170ff142cee5e6a7e2efc553e42c4184652ca3c8885a184ef9742c60c6454`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## verify_account_delete_token

```sql
create or replace function verify_account_delete_token(p_deleteTokenHash text) returns table(result boolean,code text,workflow smallint) language plpgsql
```

Source line: 3936. Definition SHA256: `989c1b0b3135eaec3782d3b1949a317581214eaa8d4330313403af55e9007f15`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## purge_expired_delete_standby

```sql
create or replace function purge_expired_delete_standby(p_now timestamptz default now()) returns table(result boolean,code text,deleted_count integer) language plpgsql
```

Source line: 3957. Definition SHA256: `0b1cd3ba50a51fa1097f5c85a5c1d000e0e8844522f7aa837790ef47b2aa18d7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## view_account

```sql
create or replace function view_account( p_accountId uuid, p_accountSecurityStamp uuid) returns table( result boolean, code text, email_address text, username text, created_on timestamp with time zone, verify_status smallint, country smallint, features smallint, two_factor_enabled boolean, two_factor_configuration smallint, two_factor_methods smallint[], entitlement_json text) language plpgsql volatile
```

Source line: 3972. Definition SHA256: `fbc4e160db6fdfa2ab8d11743560c8fcc92ecaee7d5723a4807d6b350c278663`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## lookup_locked_recovery_account

```sql
create or replace function lookup_locked_recovery_account( p_identifier text, p_now timestamp with time zone) returns table( result boolean, code text, account_id uuid, email_address text, phone_number text, phone_country_code text, account_security_stamp uuid, unlock_when timestamp with time zone, lockout_attempt_version uuid) language plpgsql
```

Source line: 4088. Definition SHA256: `ba37a8c1d740df5b2dbf9c3977b4ae5d7f4f45061a4a70c5f162a0dbc924ffea`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## start_unlock_account

```sql
create or replace function start_unlock_account( p_accountId uuid, p_tokenHash text, p_createdOn timestamp with time zone, p_expiration timestamp with time zone, p_status smallint, p_method smallint, p_accountSecurityStamp uuid, p_lockoutUnlockWhen timestamp with time zone, p_lockoutAttemptVersion uuid) returns table(status smallint) language plpgsql
```

Source line: 4131. Definition SHA256: `a5a4f3dee6b851694aeeb37ddf1e11fc7fd4bdb190ae1c25efcfb22a4b553437`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_unlock_account

```sql
create or replace function cancel_unlock_account( p_accountId uuid, p_tokenHash text) returns table(status smallint) language plpgsql
```

Source line: 4221. Definition SHA256: `9cecb57f3360e32823d6930681044fba1c882c7a38588b735adf187e00d87fa3`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## verify_unlock_account

```sql
create or replace function verify_unlock_account(p_tokenHash text) returns table(status smallint) language plpgsql
```

Source line: 4261. Definition SHA256: `7e55795e3981c118b746838b10f2b417d2f9c1483f33e5bea40815d261974d66`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## lookup_password_reset_account

```sql
create or replace function lookup_password_reset_account( p_identifier text, p_now timestamp with time zone) returns table( result boolean, code text, account_id uuid, email_address text, phone_number text, phone_country_code text, account_security_stamp uuid, email_verified boolean, sms_verified boolean, authenticator_verified boolean) language plpgsql
```

Source line: 4365. Definition SHA256: `b84a65b5f5e2f7bc5a8eaa07127655d2e367ce118a62c9aeaad6b3adb0680282`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_password_reset_totp_enrollment

```sql
create or replace function get_password_reset_totp_enrollment( p_accountId uuid, p_now timestamp with time zone) returns table( account_id uuid, two_factor_index bigint, method smallint, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint) language sql stable
```

Source line: 4468. Definition SHA256: `ff700b600094ded9e6befd540a4f439639711f50f00ca2e0d1a1ccf8426c370a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## mark_password_reset_totp_step_used

```sql
create or replace function mark_password_reset_totp_step_used( p_accountId uuid, p_twoFactorIndex bigint, p_timeStep bigint, p_enrollmentId uuid) returns table( result boolean, code text) language sql
```

Source line: 4495. Definition SHA256: `d159af4688968424b6b83a8620d0bcbf20d25255dd060d2e42b3c11d4925097a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## register_password_reset_request_rate_limit

```sql
create or replace function register_password_reset_request_rate_limit( p_rateLimitKey text, p_now timestamp with time zone, p_requestWindow interval, p_requestLimit integer, p_requestCooldown interval, p_blockPeriod interval) returns table( result boolean, code text, request_count integer, blocked_until timestamp with time zone, retry_after_seconds integer) language plpgsql
```

Source line: 4509. Definition SHA256: `1c18c17b7697d84fd759a868dac2c7cd2a76e0075e517e5037b5296d6e048941`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cleanup_password_reset_rate_limits

```sql
create or replace function cleanup_password_reset_rate_limits( p_now timestamp with time zone, p_retention interval) returns table( result boolean, code text, deleted_count integer) language plpgsql
```

Source line: 4602. Definition SHA256: `6c66138af4664b8b02b31245c5d009afe7578c11e92ea19f2276dcc6047ad828`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## create_password_reset_request

```sql
create or replace function create_password_reset_request( p_passwordResetRequestId uuid, p_accountId uuid, p_method text, p_deliveryChannel text, p_keyCodeHash text, p_keyCodeHashVersion integer, p_destinationFingerprint text, p_destinationMasked text, p_requiresKeyCode boolean, p_requiresTotp boolean, p_expiresAt timestamp with time zone, p_maxAttempts integer, p_requestedByIp inet, p_requestedByUserAgent text, p_accountSecurityStampAtRequest uuid) returns table( result boolean, code text, password_reset_request_id uuid, account_id uuid, expires_at timestamp with time zone) language plpgsql
```

Source line: 4626. Definition SHA256: `18c277825bb6f22e193fb3938aacbba7777f90a64aa5a940d5b642b09b29a4a0`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_password_reset_request

```sql
create or replace function cancel_password_reset_request( p_passwordResetRequestId uuid, p_cancelledAt timestamp with time zone, p_reasonCode text) returns table( result boolean, code text, account_id uuid, cancelled_at timestamp with time zone) language plpgsql
```

Source line: 4780. Definition SHA256: `0eef402a8d839e7b67ccc4d52eeb25d6e70dca0c0c15b16e7e7ada8494661476`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor13_reset_policy

```sql
create or replace function cor13_reset_policy(p_account uuid) returns text language sql stable set timezone = 'UTC'
```

Source line: 4843. Definition SHA256: `1dcdc759fc3553f0da3e1fa2ad36f423c520bd4703dc749173c10a230891907e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor13_reset_configurations

```sql
create or replace function cor13_reset_configurations(p_account uuid,p_bootstrap smallint) returns smallint[] language plpgsql
```

Source line: 4852. Definition SHA256: `461e87b4f56858701bd9d2f2916ddab6f53dccb82a007c071dece4cdb0346b9f`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_pending_password_reset_session

```sql
create or replace function get_pending_password_reset_session( p_resetAccessTokenHash text) returns table( password_reset_request_id uuid, account_id uuid, reset_access_token_hash text, bootstrap_proof smallint, state smallint, available_configurations smallint[], selected_two_factor_configuration smallint, required_methods smallint[], completed_methods smallint[], current_expected_method smallint, challenge_code_hash text, challenge_expiration timestamp with time zone, challenge_attempts integer, challenge_resends integer, next_challenge_allowed_at timestamp with time zone, created_on timestamp with time zone, expires_at timestamp with time zone, selected_at timestamp with time zone, two_factor_completed_at timestamp with time zone, password_changed_at timestamp with time zone, session_version bigint, challenge_version bigint, factor_policy_version text, account_security_stamp uuid) language sql stable
```

Source line: 4872. Definition SHA256: `d30ba50a1fc076d956c26fc351a2a37af4d14a201a133ad59e01205c80e30c05`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## transition_pending_password_reset_session

```sql
create or replace function transition_pending_password_reset_session( p_resetAccessTokenHash text, p_passwordResetRequestId uuid, p_accountId uuid, p_bootstrapProof smallint, p_state smallint, p_availableConfigurations smallint[], p_selectedTwoFactorConfiguration smallint, p_requiredMethods smallint[], p_completedMethods smallint[], p_currentExpectedMethod smallint, p_challengeCodeHash text, p_challengeExpiration timestamp with time zone, p_challengeAttempts integer, p_challengeResends integer, p_nextChallengeAllowedAt timestamp with time zone, p_createdOn timestamp with time zone, p_expiresAt timestamp with time zone, p_selectedAt timestamp with time zone, p_twoFactorCompletedAt timestamp with time zone, p_passwordChangedAt timestamp with time zone, p_transition smallint, p_expectedSessionVersion bigint, p_expectedChallengeVersion bigint, p_bootstrapCodeHash text) returns table(result boolean, code text, session_version bigint, challenge_version bigint, factor_policy_version text, account_security_stamp uuid) language plpgsql
```

Source line: 4931. Definition SHA256: `b6fae9e956db935c2d84678915061139eb15b721616846d9e11160e19c12c40d`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## revoke_pending_password_reset_session

```sql
create or replace function revoke_pending_password_reset_session( p_resetAccessTokenHash text, p_revokedAt timestamp with time zone, p_reasonCode text, p_expectedSessionVersion bigint, p_expectedChallengeVersion bigint) returns table(result boolean, code text) language plpgsql
```

Source line: 5098. Definition SHA256: `ec977e08f8cf4a727c7be2bb40ea102678744676b894c72da951cb896517b8bf`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## revoke_pending_password_reset_sessions_for_account

```sql
create or replace function revoke_pending_password_reset_sessions_for_account( p_accountId uuid, p_revokedAt timestamp with time zone, p_reasonCode text) returns table(result boolean, code text, revoked_count integer) language plpgsql
```

Source line: 5139. Definition SHA256: `baf9a513825880a41a57e7e0987b3517fc359ec0fd059279aaf11648c4072a8b`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_password_reset_request_for_finalize

```sql
create or replace function get_password_reset_request_for_finalize( p_passwordResetRequestId uuid) returns table( result boolean, code text, password_reset_request_id uuid, account_id uuid, method text, delivery_channel text, key_code_hash text, key_code_hash_version integer, requires_key_code boolean, requires_totp boolean, expires_at timestamp with time zone, consumed_at timestamp with time zone, cancelled_at timestamp with time zone, attempt_count integer, max_attempts integer, account_security_stamp_at_request uuid, email_verified boolean, sms_verified boolean, authenticator_verified boolean, current_email_address text, current_phone_number text, current_phone_country_code text) language plpgsql
```

Source line: 5190. Definition SHA256: `40f61866efc77a0a3ce1bb89e00f63a6ea9203138b3fbe46098d22265ba2a9d2`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## register_password_reset_failed_attempt

```sql
create or replace function register_password_reset_failed_attempt( p_passwordResetRequestId uuid, p_failedAt timestamp with time zone) returns table( result boolean, code text, account_id uuid, attempt_count integer, max_attempts integer, cancelled_at timestamp with time zone) language plpgsql
```

Source line: 5295. Definition SHA256: `72a2e78d85db6e01b7e66b82bc646503ef93324793bea8b03a7e50d5be640207`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## promote_password_reset

```sql
create or replace function promote_password_reset( p_passwordResetRequestId uuid, p_accountId uuid, p_hashedPassword bytea, p_saltOne bytea, p_siv bytea, p_nonce bytea, p_newSecurityStamp uuid, p_promotedAt timestamp with time zone, p_resetAccessTokenHash text, p_expectedSessionVersion bigint, p_expectedChallengeVersion bigint) returns table( result boolean, code text, account_id uuid, account_security_stamp uuid, consumed_at timestamp with time zone) language plpgsql
```

Source line: 5389. Definition SHA256: `b6a108003fc19b28424e1a3e1161d24ab11da9de5116b285581560672d928be8`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cleanup_expired_password_reset_requests

```sql
create or replace function cleanup_expired_password_reset_requests( p_now timestamp with time zone, p_retention interval) returns table( result boolean, code text, cancelled_count integer, deleted_count integer) language plpgsql
```

Source line: 5563. Definition SHA256: `05124dca2f7d92559e0d1a497ef15a908455c87f137a4e5d6a4c188891ade2be`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## place_activation

```sql
create or replace function place_activation( p_accountId uuid, p_accountSecurityStamp uuid, p_emailAddress text, p_code text, p_createdOn timestamp with time zone, p_term smallint, p_interval smallint, p_closeOff timestamp with time zone, p_featureSet smallint, p_platformBacker smallint, p_platformText text, p_status smallint, p_delayedStart interval) returns table(result boolean, code text, status smallint) language plpgsql
```

Source line: 5611. Definition SHA256: `db66778c1c35139ee8c9030384b22c76cce07a27b373ffa9d3e3ad1ac86647b7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cancel_activation_request

```sql
create or replace function cancel_activation_request( p_accountId uuid, p_accountSecurityStamp uuid, p_code text, p_cancelledOn timestamp with time zone) returns table(result boolean, code text, status smallint) language plpgsql
```

Source line: 5633. Definition SHA256: `b3e7bf21d89225cce3fd659834c228ea97651436f5130ce6db3b543eb1beb4d0`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## disable_activation

```sql
create or replace function disable_activation( p_accountId uuid, p_accountSecurityStamp uuid, p_emailAddress text, p_createdOn timestamp with time zone, p_closeOff timestamp with time zone, p_status smallint) returns table(result boolean, code text, status smallint) language plpgsql
```

Source line: 5646. Definition SHA256: `37f1a2b4f6896b907450e4878ade63f243ae4eee585afcc2c996eea7fd723f99`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## verify_activation

```sql
create or replace function verify_activation( p_accountId uuid, p_accountSecurityStamp uuid, p_emailAddress text, p_code text, p_createdOn timestamp with time zone, p_position smallint, p_upperLimit smallint) returns table( result boolean, code text, feature_set smallint, off_at timestamp with time zone, day_duration smallint, duration_repeat smallint) language plpgsql
```

Source line: 5661. Definition SHA256: `4ab685ccd291a39d7d9788b093f27b96285eb43ebaf60432fd1d5e7c8fc68ce2`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## session_refresh_credential_hash

```sql
create or replace function session_refresh_credential_hash(p_key bytea,p_identity uuid) returns text language sql immutable
```

Source line: 5701. Definition SHA256: `818290249ff6d480a079f97f9f43b1ccee76ce043a6f1a40154bff68d134f970`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## get_refresh_session

```sql
create or replace function get_refresh_session(p_hash text,p_family uuid,p_generation bigint) returns table(account_id uuid,refresh_token bytea,refreshes smallint,refresh_limit smallint, created_on timestamptz,session_lifespan interval,access_expiration timestamptz, session_expiration timestamptz,cut_off timestamptz,features smallint,security_stamp uuid, account_security_stamp uuid,session_id uuid,generation bigint,protocol_version integer, access_token_hash text,web_key text, entitlement_json text) language plpgsql volatile
```

Source line: 5711. Definition SHA256: `0232f7dd40da0f2f3ede2959d06c70e3410bafad1d15f3c6f07f38cba205a2ac`.

Lexical C# references: `Repos/SessionRefreshRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## refresh_session

```sql
create or replace function refresh_session(p_account uuid,p_stamp uuid,p_family uuid,p_generation bigint, p_old_hash text,p_refresh_hash text,p_new_hash text,p_key bytea,p_identity uuid, p_access_seconds integer,p_minimum_interval integer) returns table(result boolean,code text,access_expiration timestamptz,session_expiration timestamptz,cut_off timestamptz,entitlement_json text) language plpgsql
```

Source line: 5738. Definition SHA256: `c6d69f32d4c629f26579797513a2231e79b6a26b5a7cfb4cdc7fbeacaae1a31e`.

Lexical C# references: `Repos/SessionRefreshRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_login_snapshot

```sql
create or replace function cor10_login_snapshot(p_hash text) returns jsonb language sql volatile
```

Source line: 5793. Definition SHA256: `ee03109406615603e6ad1616b271717405e8aa7e43778eafc5d82f7b93b11983`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_lock_login

```sql
create or replace function cor10_lock_login(p_hash text,p_stamp uuid,p_version bigint) returns pending_two_factor_sessions language plpgsql
```

Source line: 5815. Definition SHA256: `e527108d65e2b64b5ecf0ef84bcacfe5848d3ae85e32cddcf712b25551e16fc9`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_begin_login

```sql
create or replace function cor10_begin_login(p_hash text,p_snapshot jsonb) returns table(result boolean,code text,snapshot text) language plpgsql
```

Source line: 5836. Definition SHA256: `95f7d645135b3f0addfd78654edf1c2f21509527090be647cf83253ac71ac9c4`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_issue_challenge

```sql
create or replace function cor10_issue_challenge(p_hash text,p_stamp uuid,p_version bigint,p_configuration smallint, p_method smallint,p_destination smallint,p_verifier text,p_expires timestamptz,p_limit smallint,p_cooldown integer) returns table(result boolean,code text,snapshot text) language plpgsql
```

Source line: 5871. Definition SHA256: `f37ae25b607cb6977edc1ee12dbf1fbc96d84ce6f5275485783979e292cd2a6c`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_cancel_challenge

```sql
create or replace function cor10_cancel_challenge(p_hash text,p_stamp uuid,p_version bigint,p_challenge uuid) returns table(result boolean,code text,snapshot text) language plpgsql
```

Source line: 5917. Definition SHA256: `65758a2feb9238a63b7cccbdee5e2d2e656447296a6258b8fc0ac5e4464a0d71`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor10_complete_proof

```sql
create or replace function cor10_complete_proof(p_hash text,p_stamp uuid,p_version bigint,p_challenge uuid,p_method smallint, p_verifier text,p_totp boolean,p_limit smallint) returns table(result boolean,code text,snapshot text) language plpgsql
```

Source line: 5938. Definition SHA256: `bb0497b17df6f4c60e9cd42b556a16e5680ff99043a3e5403e32df75cd242be8`.

Lexical C# references: `Repos/LoginProofRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_delivery_predecessor

```sql
create or replace function cor12_delivery_predecessor(p_account uuid,p_purpose text) returns text language plpgsql stable
```

Source line: 5980. Definition SHA256: `91ed19e4aa3bde03d99ee8eac0b159be4777ab6e87262a6bb0433d6890bd1781`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_lock_delivery

```sql
create or replace function cor12_lock_delivery(p_account uuid) returns void language plpgsql
```

Source line: 5998. Definition SHA256: `3d5211738c93c38a25a513fa179e789ee11a3e19a90dbaf26c8db52104811521`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_delivery_is_pending

```sql
create or replace function cor12_delivery_is_pending(p_purpose text,p_hash text,p_account uuid default null) returns boolean language plpgsql
```

Source line: 6008. Definition SHA256: `ac5f9f71c9457351d38acca0f938ce95d92fd98983fa36e7afa74e84a1029a59`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_expire_delivery

```sql
create or replace function cor12_expire_delivery(p_id uuid) returns void language plpgsql
```

Source line: 6020. Definition SHA256: `3181c13be0fed4eb96c66bf269a97b621c853bb7fbc58a55defc755e94dd8947`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_stage_delivery

```sql
create or replace function cor12_stage_delivery(p_id uuid,p_account uuid,p_stamp uuid,p_purpose text,p_hash text, p_expires timestamptz,p_metadata text,p_key integer,p_nonce bytea,p_cipher bytea,p_tag bytea,p_noticeId uuid default null,p_noticeKey integer default null,p_noticeNonce bytea default null,p_noticeCipher bytea default null,p_noticeTag bytea default null,p_noticeMetadata text default null) returns table(result boolean,code text,delivery_id uuid) language plpgsql
```

Source line: 6033. Definition SHA256: `04b157caf73e087acd1331a6bef99434fe9114b47a2ecf48d3aafe891bae9ef8`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23j_delivery_can_send

```sql
create or replace function cor23j_delivery_can_send(p_id uuid,p_lease uuid) returns boolean language plpgsql
```

Source line: 6151. Definition SHA256: `d943f9b7641ce36ed40a1edfc173facb5baee7c0db43bb54f0cfa352acf43aa0`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_claim_delivery

```sql
create or replace function cor12_claim_delivery(p_lease uuid,p_seconds integer,p_max integer) returns table(delivery_id uuid,account_id uuid,account_stamp uuid,purpose text,proof_hash text,expires_at timestamptz, metadata_json text,key_version integer,nonce bytea,ciphertext bytea,tag bytea,state text,lease_id uuid,attempts integer) language plpgsql
```

Source line: 6180. Definition SHA256: `a38ec9d8289e7ad7c0a401a389a83e147a80b6091ec0d71b01ba4580fa47f436`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_record_delivery

```sql
create or replace function cor12_record_delivery(p_id uuid,p_lease uuid,p_state text,p_max integer, p_provider text default 'none',p_receipt text default null,p_retry boolean default false,p_code text default 'DELIVERY_OUTCOME') returns boolean language plpgsql
```

Source line: 6238. Definition SHA256: `b6e7ad67f4e95ebb2b98c89fcaa6bc4b63b71d195b20f375340efc136bd243e8`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_publish_delivery

```sql
create or replace function cor12_publish_delivery(p_id uuid) returns boolean language plpgsql
```

Source line: 6278. Definition SHA256: `dde9363405a379fba85096e590d0b8063f207ec8bec47bda646f5c3a44d24ebd`.

Lexical C# references: `Repos/DeliveryOutboxRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor12_cancel_delivery

```sql
create or replace function cor12_cancel_delivery(p_id uuid,p_account uuid,p_stamp uuid) returns boolean language plpgsql
```

Source line: 6338. Definition SHA256: `2c7a2f5bc1583abe647124c0578f7943397a6bcd4d2ac538fd50217b1db8a5e1`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor15_reencrypt_totp

```sql
create or replace function cor15_reencrypt_totp( p_accountId uuid, p_enrollmentId uuid, p_expectedVersion bigint, p_oldKeyId text, p_newKeyId text, p_ciphertext bytea, p_nonce bytea, p_tag bytea) returns boolean language plpgsql
```

Source line: 6351. Definition SHA256: `d8d4c8ce12650782913bda7fac2f158f91527c5992e9daac38535dcc2c6678ca`.

Lexical C# references: `Repos/TotpReencryptionRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor16_clear_setup_authority

```sql
create or replace function cor16_clear_setup_authority() returns trigger language plpgsql
```

Source line: 6373. Definition SHA256: `9047cf00e4559b355e640398ae1791b702728621e3cae075bc749eeda8b0981e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor16_require_setup

```sql
create or replace function cor16_require_setup(p_row two_factor_authentications,p_stamp uuid,p_family uuid) returns void language plpgsql
```

Source line: 6393. Definition SHA256: `50706b1b1f68c3e7e1481b9776b99fac202db2d0f0f8f96c6d9ebc12858edafc`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor16_bind_setup

```sql
create or replace function cor16_bind_setup(p_account uuid,p_index bigint,p_request uuid,p_version bigint,p_grant text) returns void language plpgsql
```

Source line: 6411. Definition SHA256: `424daf6a5482fe9f02b37ce4a654e221823b9e4a85b0fdce16ccce783a4830d7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor16_factor_changed

```sql
create or replace function cor16_factor_changed(p_account uuid) returns void language plpgsql
```

Source line: 6425. Definition SHA256: `51e9efe9163b39c0077a4fb9c1f83879de551245b04384a566041352a517ae45`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor16_begin_twofactor_setup

```sql
create or replace function cor16_begin_twofactor_setup(p_accountId uuid,p_accountSecurityStamp uuid,p_method smallint,p_tokenHash text, p_createdOn timestamptz,p_expiration timestamptz,p_emailAddress text,p_phoneNumber text,p_phoneCountryCode text,p_authId text,p_required boolean, p_requestId uuid,p_expectedRequestId uuid,p_expectedVersion bigint,p_grantSession text,p_grantToken text,p_grantTarget text) returns table(result boolean,code text,two_factor_index bigint,expiration timestamptz) language plpgsql
```

Source line: 6438. Definition SHA256: `182a8e0f2c5b6a01faf974a0bc18ae81d11e37c10e3ba678c4daa7890814530e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor17_email_gate

```sql
create or replace function cor17_email_gate() returns void language sql
```

Source line: 6495. Definition SHA256: `54e5a4ca74bde6c0d9c32f3db62876a3327f02b48fb32a993a5e1eb63ffee7a1`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor17_email_live

```sql
create or replace function cor17_email_live(p_row account_email_change_requests) returns boolean language plpgsql
```

Source line: 6497. Definition SHA256: `3aa22c456c4b295de8ff534fd8692854a1164c6bcaa6386d552de3fcbd92016e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor17_retire_email_request

```sql
create or replace function cor17_retire_email_request(p_account uuid,p_hash text) returns integer language plpgsql
```

Source line: 6509. Definition SHA256: `c877673f4decb4742158196e31f02248ad16ffd153518bae1053ced5a69af5ef`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor17_purge_email_requests

```sql
create or replace function cor17_purge_email_requests() returns integer language plpgsql
```

Source line: 6520. Definition SHA256: `2fed9d5b2aa46d97af81736b152a0aeadbe959b516347013cd3b3984f15ef5c3`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor17_authorized_request_email

```sql
create or replace function cor17_authorized_request_email(p_account uuid,p_stamp uuid,p_email text,p_hash text,p_expires timestamptz,p_request uuid,p_session text,p_grant text,p_target text,p_origin text) returns table(result boolean,code text,email_address text) language plpgsql
```

Source line: 6543. Definition SHA256: `84969eb25b6327bccce0b33e3a092f32f88fe226a9aebdaa369204fe0624ae64`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_origin_live

```sql
create or replace function cor18_origin_live(p_account uuid,p_stamp uuid,p_email text,p_family uuid,p_policy text,p_until timestamptz,p_expires timestamptz) returns boolean language plpgsql
```

Source line: 6573. Definition SHA256: `b84a85a206dc814da6670394e88ad8ba01fd383436058c3482a0acf0305af99c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_delete_live

```sql
create or replace function cor18_delete_live(p_row delete_standby) returns boolean language plpgsql
```

Source line: 6580. Definition SHA256: `6cf61fd5bf0f1887c4dc8a120f7529b755acc9e3b005d8e023f57b9d47af7434`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_admission_live

```sql
create or replace function cor18_admission_live(p_row account_delete_admissions) returns boolean language plpgsql
```

Source line: 6584. Definition SHA256: `3adab85ef8d210a99947a1892b1c4fb43024e5a2bb6bcfe415f9fc7de3e6650c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_retire_delete

```sql
create or replace function cor18_retire_delete(p_account uuid,p_hash text) returns void language plpgsql
```

Source line: 6588. Definition SHA256: `1f9e67eba57359b3fd36bd4d015e33b482e5c87041e47b308bfc3e47aff1b2f2`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_revoke_delete

```sql
create or replace function cor18_revoke_delete(p_account uuid) returns void language plpgsql
```

Source line: 6596. Definition SHA256: `dfe1904a328c256bdd8ccc77421dc526e9a5a295572ba79a5171eb904fca8e33`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_admit_delete

```sql
create or replace function cor18_admit_delete(p_account uuid,p_stamp uuid,p_id uuid,p_hash text,p_expires timestamptz,p_cooldown interval,p_window interval,p_max smallint,p_session text,p_grant text,p_target text) returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql
```

Source line: 6603. Definition SHA256: `5f87a1c8090f1d25ae67ecbccb81aeec14d653212aeac18d9ac369da82da3450`.

Lexical C# references: `Repos/AccountRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_stage_delete

```sql
create or replace function cor18_stage_delete(p_account uuid,p_stamp uuid,p_admission uuid,p_hash text,p_expires timestamptz,p_passphrase text) returns table(result boolean,code text) language plpgsql
```

Source line: 6632. Definition SHA256: `f6036d1e1df7b55e82abc8ed5f75c17ca1ebb64af2a00b94a2058f8f2975e366`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_finalize_denial

```sql
create or replace function cor18_finalize_denial(p_row delete_standby,p_stamp uuid,p_session text,p_max smallint,p_lockout interval) returns text language plpgsql
```

Source line: 6649. Definition SHA256: `8ec865fb32e7837765fce02e68daa340767d321eabb3cb31ba0b915461d94b8c`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_account_security_event

```sql
create or replace function cor18_account_security_event() returns trigger language plpgsql
```

Source line: 6662. Definition SHA256: `f17f984d06c8ff9d40e07328bf33568c8e5cd8d2f92bdfa59c594206a7dc2b27`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_family_security_event

```sql
create or replace function cor18_family_security_event() returns trigger language plpgsql
```

Source line: 6668. Definition SHA256: `bcd2ce31bf2ce02031ec4f59de8afb17ae06f9b84ddf389dc53b406b2c982efe`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor18_factor_security_event

```sql
create or replace function cor18_factor_security_event() returns trigger language plpgsql
```

Source line: 6681. Definition SHA256: `1431376841e27ccb176cd8c5d7f5557ebb2548596eef74706b0c0262004ff1a1`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_is_issuer

```sql
create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable
```

Source line: 6695. Definition SHA256: `b285728d8dc9bd6c78b924e2accf648b8f499e450789317636fa8ffb4c888702`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_audit

```sql
create or replace function cor19_audit(p_grant uuid,p_action text,p_actor text,p_stamp uuid,p_family uuid,p_approval jsonb default null) returns void language plpgsql
```

Source line: 6705. Definition SHA256: `f7eed2c015f2fa4b4b6b57a2b1258c5fe1549ff358bc8aa31ee8c45297e010b4`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_issue_grant

```sql
create or replace function cor19_issue_grant(p_grant uuid,p_account uuid,p_stamp uuid,p_catalog text,p_tier smallint,p_term smallint,p_cadence smallint,p_start timestamptz,p_end timestamptz,p_cycles integer,p_redeem timestamptz,p_reference text,p_anchor text,p_denied text[]) returns table(result boolean,code text) language plpgsql
```

Source line: 6713. Definition SHA256: `97e9e66730fac59fda4588d8584ac15ad347ec8dd7d46a7436a831c4d2045d62`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_grant_live

```sql
create or replace function cor19_grant_live(p_grant uuid,p_account uuid,p_stamp uuid,p_version bigint) returns boolean language plpgsql volatile
```

Source line: 6738. Definition SHA256: `2db9a7f54a23fce6ee752417757debfeae0858974ce4cda037cfa1a490d212fb`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_stage_activation

```sql
create or replace function cor19_stage_activation(p_request uuid,p_account uuid,p_stamp uuid,p_session text,p_family uuid,p_grant uuid,p_version bigint,p_hash text,p_expires timestamptz,p_email text,p_tier smallint,p_term smallint,p_cadence smallint,p_admission uuid default null) returns table(result boolean,code text) language plpgsql
```

Source line: 6744. Definition SHA256: `ef2f48ab7fc06f3898b71b7ad01608965040c8dc29b08c7d630ab9d34a6d80ae`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_request_live

```sql
create or replace function cor19_request_live(p_request uuid,p_stamp uuid,p_hash text) returns boolean language plpgsql volatile
```

Source line: 6769. Definition SHA256: `3ce4b2ac30bea8e237cdcf90048bfaddd5178db4fbed48538eab08052c1f2fe7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_publish_activation

```sql
create or replace function cor19_publish_activation(p_request uuid,p_stamp uuid,p_hash text) returns boolean language plpgsql
```

Source line: 6777. Definition SHA256: `f555b84c0a5989ba4b0584e2fe3b7cc76a27b4720af4f855b432c5b3597ce2b5`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_transition_activation

```sql
create or replace function cor19_transition_activation(p_account uuid,p_stamp uuid,p_session text,p_family uuid,p_grant uuid,p_version bigint,p_request uuid,p_hash text,p_action text) returns table(result boolean,code text,grant_version bigint,starts_at timestamptz,eligibility_until timestamptz,entitlement_json text,term smallint,tier smallint,cadence smallint) language plpgsql
```

Source line: 6789. Definition SHA256: `b54cc80cbed322a3748430dd3a302e8a6b39c3fd20b0b93a3f2e59bda2d771f7`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor19_protect_audit

```sql
create or replace function cor19_protect_audit() returns trigger language plpgsql security definer
```

Source line: 6841. Definition SHA256: `7dad2598c2ce336d9e64fc465f6ad29a6a42e28155c50c9f74ed514d3f7ff5d5`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_now

```sql
create or replace function cor20_now() returns timestamptz language plpgsql volatile
```

Source line: 6857. Definition SHA256: `c0c08066956474b6b3a444fa225bf2a082da8d3b5d72873c02a0ed4483ba6694`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_grant_rights_enabled

```sql
create or replace function cor20_grant_rights_enabled() returns boolean language plpgsql stable
```

Source line: 6860. Definition SHA256: `eef08b420b34a72cb62533183001255d8d9828723edf51cbdaa878b4809c8975`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_capabilities

```sql
create or replace function cor20_capabilities(p_tier smallint) returns text[] language plpgsql immutable
```

Source line: 6863. Definition SHA256: `6ffc36035280e3f659044998ef61627a2ca0f3161c7d2d1d5fff4e5bc6b26fe4`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_term_boundary

```sql
create or replace function cor20_term_boundary(p_start timestamptz,p_term smallint,p_cycle integer) returns timestamptz language plpgsql immutable
```

Source line: 6869. Definition SHA256: `45528a95b64ea00ece900e5e6343389c5961efb0f16484cb01422e7207f4692a`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_cycle_at

```sql
create or replace function cor20_cycle_at(p_start timestamptz,p_term smallint,p_max integer,p_until timestamptz,p_now timestamptz) returns integer language plpgsql immutable
```

Source line: 6890. Definition SHA256: `56b4881badc4f9babb5400e3c9ebd8159871cc339dfcbdeade1e8ccc67505bd5`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_approval_audited

```sql
create or replace function cor20_approval_audited(p_grant uuid) returns boolean language plpgsql volatile
```

Source line: 6906. Definition SHA256: `dad307f7034fe5b94b2b8d3a405582aa0414ce45f6fbe34e15b4093835349a57`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_activation_audited

```sql
create or replace function cor20_activation_audited(p_grant uuid) returns boolean language plpgsql volatile
```

Source line: 6921. Definition SHA256: `e8be395439fe7c8a8f67bec59033d7fffc4773bb0246b597099b324cd0f16109`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_resolve_account

```sql
create or replace function cor20_resolve_account(p_account uuid) returns jsonb language plpgsql volatile
```

Source line: 6931. Definition SHA256: `202aad225dcc2483ff6102be3883045fd7e4e207f16ef6813dc6bf24339ad81a`.

Lexical C# references: `Repos/EntitlementRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_grant_projection_event

```sql
create or replace function cor20_grant_projection_event() returns trigger language plpgsql
```

Source line: 6992. Definition SHA256: `d48529185b190d162c4846fb97f8c9698adc6f936057a88623578f894be9c885`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_materialize_cycles

```sql
create or replace function cor20_materialize_cycles(p_account uuid,p_limit integer) returns integer language plpgsql
```

Source line: 7000. Definition SHA256: `f48ee8def6f7452dffecca411cf6274911dfdfb501d9f816398bd377a869733f`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_renew_batch

```sql
create or replace function cor20_renew_batch(p_limit integer) returns table(result boolean,code text,renewed_cycles integer) language plpgsql
```

Source line: 7035. Definition SHA256: `d25e0a14c19c5f3e5598b924336ba0fbd98b38a1883e2e9f7343503f294c0374`.

Lexical C# references: `Repos/EntitlementRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor20_session_projection_insert

```sql
create or replace function cor20_session_projection_insert() returns trigger language plpgsql
```

Source line: 7050. Definition SHA256: `2f6569d3d70e816c90b8a516c1ec25915cea767fb4dbb27cbb4d8875f0d9c8b5`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor21_admit_creation

```sql
create or replace function cor21_admit_creation(p_account uuid,p_stamp uuid,p_session text,p_family uuid, p_grant uuid,p_version bigint,p_hash text,p_email text,p_tier smallint,p_term smallint,p_cadence smallint,p_ip text, p_account_max integer default 5,p_identifier_max integer default 5,p_ip_max integer default 50, p_window integer default 900,p_cooldown integer default 60) returns table(result boolean,code text,admission_id uuid,retry_after_seconds integer) language plpgsql
```

Source line: 7082. Definition SHA256: `b495c500258528c91772270997774fc1442d79cbce5f7927f9c1ec2be8b5e914`.

Lexical C# references: `Repos/ActivationRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor21_creation_live

```sql
create or replace function cor21_creation_live(p_admission uuid,p_account uuid,p_stamp uuid,p_family uuid,p_grant uuid,p_version bigint,p_hash text) returns boolean language sql volatile
```

Source line: 7144. Definition SHA256: `331a957a803507caf173d6a04e4f5058e2102f38a57102d2aa7ff5e59baae71e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_grant_obsolete

```sql
create or replace function cor22_grant_obsolete(g entitlement_grants,p_history integer) returns boolean language sql volatile
```

Source line: 7169. Definition SHA256: `9cae1667e5364d637762b52089f3b66e6c3c6227073f00865fb8f9442b087637`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_account_empty

```sql
create or replace function cor22_account_empty(p_account uuid) returns boolean language plpgsql
```

Source line: 7179. Definition SHA256: `eb148d830d25890ea4fad40e7d8fc0da407239486468d5ad2a576114f4d0c7de`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_retention_policy

```sql
create or replace function cor22_retention_policy(p_job text) returns table(table_name text,key_sql text,account_sql text,predicate_sql text) language plpgsql
```

Source line: 7196. Definition SHA256: `77f85a70f84a124c419c93f02f634893e1ff78116474f63d529e2329b344e13e`.

Lexical C# references: none indexed; classify at native repository/SQL review.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_claim_retention

```sql
create or replace function cor22_claim_retention() returns table(job_name text,lease_id uuid) language plpgsql security definer
```

Source line: 7241. Definition SHA256: `b166abd0f417b87a0648a5d3bf8557483c472cff9d42007d6d55f3e532332a6a`.

Lexical C# references: `Repos/RetentionRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_fail_retention

```sql
create or replace function cor22_fail_retention(p_job text,p_lease uuid,p_code text) returns boolean language plpgsql security definer
```

Source line: 7255. Definition SHA256: `1a28aa659d0e77b2f82786be4baac3ae46e59b4ae652ce8fa07f1e1e15e6331e`.

Lexical C# references: `Repos/RetentionRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor22_retention_batch

```sql
create or replace function cor22_retention_batch(p_job text,p_lease uuid,p_limit integer,p_accounts integer, p_history integer,p_audit integer,p_unverified integer,p_dry boolean) returns table(eligible integer,affected integer,wrapped boolean) language plpgsql security definer
```

Source line: 7266. Definition SHA256: `af7de62c172ef3170343acb57b0ad91733579cdc26bee5e8f3b9ee07057d197c`.

Lexical C# references: `Repos/RetentionRepo.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23m_increment_budget_v1

```sql
create or replace function cor23m_increment_budget_v1(p_policy integer,p_dimension integer,p_hash bytea,p_maximum integer,p_window_ms bigint,p_cooldown_ms bigint) returns table(admitted boolean,attempts integer,retry_ms bigint,reason integer,cooldown_started boolean) language plpgsql
```

Source line: 7377. Definition SHA256: `11b332e47aa8e0a7da56f8e290c1632fd7880512034882f4ead0fc2bfcc8ff98`.

Lexical C# references: `Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23m_budget_cooldown_v1

```sql
create or replace function cor23m_budget_cooldown_v1(p_policy integer,p_dimension integer,p_hash bytea) returns bigint language plpgsql
```

Source line: 7423. Definition SHA256: `b6bd8346d9856f15c43c89ea9903777eaa5571ac7c4bb6c186b8e63fa5927478`.

Lexical C# references: `Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23m_reset_budget_v1

```sql
create or replace function cor23m_reset_budget_v1(p_policy integer,p_dimension integer,p_hash bytea) returns boolean language plpgsql
```

Source line: 7437. Definition SHA256: `bfddc413d8377be0d9fcd51e5d43fde87a410d48215b72758b4bb5ed6b2c808a`.

Lexical C# references: `Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.

## cor23m_purge_budgets_v1

```sql
create or replace function cor23m_purge_budgets_v1(p_batch integer,p_dry boolean) returns integer language plpgsql
```

Source line: 7449. Definition SHA256: `830baa69ca9557f9533f1333999feaff2ba82472a9472dc3b13693f33158a4eb`.

Lexical C# references: `Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs`.

Qualification: pending native catalog, branch/result-reader and contention evidence.
