# COR23L — selected Twilio local startup prerequisites

Date: 2026-10-09 (America/Chicago). Baseline: completed COR23K. Finding: R08-05, P2. Dependencies: COR01/COR23; coordinated with COR23D capture isolation and COR23K provider health. Status: FixedPendingQualification; qualification NotRun.

## Problem and behavior

An enabled selected Twilio primary or secondary route could pass startup with missing credentials/sender, leaving an unavailable secondary advertised as viable failover. Production DI now registers SelectedSmsTransportValidator alongside the existing bound Sidewalk options and ValidateOnStart. It normalizes the whole configured chain and checks Twilio whenever SMS and Twilio are enabled and Twilio is selected in either position. Generic route validation still rejects unsupported/duplicate/disabled selections. The failure includes every missing or invalid setting name; no configured value is included.

Disabled SMS, disabled unused Twilio and enabled unused Twilio can omit physical credentials. A selected disabled provider with SMS enabled still fails existing route validation. Disabling Twilio alone does not silently remove it from a live selected chain: remove it explicitly or configure a supported enabled replacement.

| Setting | Local application policy |
| --- | --- |
| TwilioAccountSid | Exact `AC` prefix plus 32 ASCII hexadecimal characters (34 characters total). |
| TwilioAuthToken | Required opaque token: 1–512 printable ASCII characters without whitespace or controls. No fixed 32-character/hex requirement. |
| TwilioFromPhoneNumber | E.164 phone-shaped sender: `+`, first digit 1–9, 2–15 total ASCII digits. No spaces, controls, Unicode digits, short codes, alphanumeric names or channel prefixes. |

This application's phone-number setting supports E.164 SMS phone senders. The local policy does not describe every sender type Twilio supports. Shape validity does not prove that a phone number is provisioned, owned or permitted for a specific destination. Account SID/token shape does not verify credentials. The checks use no network I/O and do not alter readiness/health endpoint behavior. Remote authentication, credit, reachability, messaging restrictions and sender ownership remain separate deployment qualification.

## Composition, runtime and diagnostics

Only the validated immutable COR23D SystemTestCapability can omit physical prerequisites when exact Testing capture replaces the physical transports. Non-Testing environments and Production database profiles cannot enable that capability. Generic options/route validations still apply in capture composition. The physical preflight intentionally rejects capture even in Testing, so fake transports cannot claim production readiness.

TwilioSmsService retains feature/payload guards and now shares the local prerequisite checker before calling ITwilioMessageClient. Missing/invalid configuration returns ConfigurationMissing with a setting name, confirmed NotSubmitted and neutral health evidence; no provider request occurs. Existing receipts, safe fallback, Unknown acceptance, deadlines, task ownership and provider-route circuits are preserved. Low-level HTTP clients remain transport implementations; the application adapter owns the runtime configuration guard.

Route-validation diagnostics also stop echoing unsupported/disabled configured provider values. Preflight binding failures use a fixed message rather than exception text. Native host regression cases capture exception strings and logger output and assert that dummy account/auth values are absent. No real credentials or external messages are used.

## Provisioning and deployment preflight

1. Provision all three settings through the deployment secret/configuration mechanism before selecting and enabling Twilio. `deploy/sms-twilio.env.example` is intentionally incomplete; it fails preflight until populated. `appsettings.Example.json` ships SMS/providers disabled with no selected chain or physical credentials.
2. Run the published application from its publish directory with the intended ASPNETCORE_ENVIRONMENT/DOTNET_ENVIRONMENT and injected configuration: `dotnet treehammock.dll validate-sms-config`. The `eng/validate-sms-config.sh` wrapper changes to that directory and preserves the process exit status. It does not trace or print environment contents.
3. Treat nonzero exit as a deployment failure. The command exits before service/host composition: no background workers, database/cache clients, provider requests or remote credential checks. It uses standard appsettings/environment overrides, strict Sidewalk binding, validated test capability, generic local route validation and the same selected transport validator. Output is setting names or fixed messages only. It is a local SMS configuration check, not comprehensive host readiness.
4. Run separate authorized remote readiness checks under the deployment policy. If a secondary cannot be provisioned, remove it explicitly rather than leaving a missing transport as fallback. To disable all SMS, set SmsEnabled=false. For AWS-only delivery, select aws-sns, clear secondary and disable unused Twilio.

Repository CI runs source/mutation guards and invokes the actual preflight on shipped disabled physical configuration after building the fast native lane. Deployment CI must repeat the published command with its own real injected settings; repository CI has no production secrets. Exact Testing capture hosts can omit physical credentials for owned fake-only tests, while the physical command refuses that composition.

## Evidence and limits

Nineteen new Python source/mutation tests are supplemental structural witnesses, not C# execution. The full tooling suite contains 248 tests. New native tests comprise 21 methods and 84 inline-expanded cases: actual Program host startup for null/empty/whitespace fields in primary and secondary positions; malformed fields; all missing fields; valid and disabled/unused matrices; normalized AWS aliases with missing Twilio secondary; exact Testing capture and non-Testing rejection; sender/SID/token boundaries; runtime non-submission; preflight exit/redaction, strict binding, optional fields and capture rejection.

Host fixtures remove background IHostedService registrations and substitute ITwilioMessageClient while retaining real Program/options/ValidateOnStart composition. They target local host startup and do not qualify worker lifecycle or remote transports. All native methods and application/cache/transport/PostgreSQL lanes remain NotRun/Blocked: this environment has no .NET SDK, PostgreSQL service/client, Docker/cache service or PowerShell. Release gates remain Open; source checks cannot close R08-05.

No SQL functions, tables, setup scripts, checksums or migration history change. All 172 SQL definitions, original review evidence/inventory, other 83 findings and all 186 release gates remain preserved. R08-05 alone moves Open → InProgress → FixedPendingQualification; resulting ledger is 64 FixedPendingQualification and 20 Open, none Closed. Greenfield pre-1.0 provisioning uses direct configuration changes, with no deployed upgrade/backfill/compatibility layer.

## Sequence correction

The frozen COR23_FOLLOWUPS.json specification assigns COR23L to selected SMS startup prerequisites. Earlier COR23J/COR23K implementation notes that associated COR23L with rendering were mistaken; they are preserved as historical evidence. This PR follows the frozen COR23L ownership, not that earlier label. Next is COR23M (R08-06), conditional PostgreSQL abuse-counter fallback. COR23N separately owns health hosted-service lifecycle.
