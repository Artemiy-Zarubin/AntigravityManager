# Agent Note: Google Forbidden Retry Parity

Status: implemented

## Problem

Google Code Assist uses HTTP 403 for project billing context, account eligibility, identity validation and organization network policy failures. Treating every 403 identically either wastes retries on an account that cannot serve traffic or removes a usable account for a recoverable verification or VPC Service Controls condition.

Live provider checks identified two durable eligibility responses: Gemini Code Assist being unavailable in the account's location and the configured account lacking a product license (`#3501`). The captured environment evidence is recorded in [Agy and Gemini OAuth Credential Synchronization](../security/2026-08-30-agy-google-oauth-file-sync.md).

## Decision

The internal Google transport sends `x-goog-user-project` when the request has a non-empty project. For ordinary generation requests, a 403 on that attempt is retried once against the same endpoint without the header. A second 403 is preserved as the final upstream error; the header downgrade does not loop or trigger 403 endpoint failover.

Weekly warmup explicitly disables the project-header downgrade. Its streaming-to-non-streaming fallback remains available only for transport failures, while either an accepted HTTP 403 response or an Axios 403 rejection surfaces immediately. This keeps one warmup candidate from starting a second generation after the provider has already returned an HTTP response.

The forbidden classifier names location ineligibility and missing Code Assist license separately from a generic forbidden account. These are durable account-level failures: after the project-context downgrade is exhausted, retry policy marks the account forbidden and selects another lease while excluding accounts already attempted by the request.

Only structured `VALIDATION_REQUIRED` responses from the supported Cloud Code domains and `SECURITY_POLICY_VIOLATED` responses remain in rotation. Unrecognized 403 responses fail closed as `account_forbidden`.

## Alternatives considered

- Use a hard-coded public Google Cloud project when account project discovery fails. Rejected because it assigns billing and policy context the user did not configure and can hide provider eligibility failures.
- Retry all 403 responses across every internal endpoint. Rejected because authorization and eligibility failures are not endpoint health failures and repeated requests add latency without changing the result.
- Keep location and license failures under `account_forbidden`. Rejected because the retry action would be correct but diagnostics could not distinguish a dead credential from a provider eligibility restriction.
- Keep every recognized 403 in rotation. Rejected because location and license restrictions are durable for the current account and would repeatedly select an account known not to serve the request.
- Remove the project-header downgrade globally. Rejected because ordinary generation requests still need the bounded recovery path for project-context incompatibility.
- Preserve the downgrade for weekly warmup. Rejected because warmup has a stricter single-generation safety contract and an HTTP rejection is not a transport failure.

## Consequences

Project billing-header incompatibility gets one bounded compatibility retry on ordinary generation requests. Weekly warmup sends only one generation for an HTTP rejection, while retaining transport-failure fallback. Durable account eligibility failures rotate to another account, and the final 403 remains available when all candidate accounts fail. Identity validation and VPC Service Controls failures do not poison otherwise usable credentials.

No fallback project, credential mutation or new retry budget is introduced.

## Verification

- `npm test -- src/tests/unit/weekly-warmup-wire.test.ts src/tests/unit/weekly-warmup-executor.test.ts src/tests/unit/weekly-warmup.test.ts src/tests/unit/proxy-retry-mock.test.ts src/tests/unit/cloud-monitor.test.ts`
- `npm run type-check`
- `npm run check:agent-contracts`
