# How to use the GitGuardian plugin

GitGuardian detects hardcoded secrets in source code, files, and messages, and manages the resulting incidents. This plugin brings the [GitGuardian public API](https://api.gitguardian.com/docs) into Kestra flows.

## Authentication

Every task and trigger authenticates with an `apiKey`: a GitGuardian personal access token or service account token created in the dashboard under **API > Personal access tokens** or **Service accounts**. Store it as a Kestra secret and reference it as `{{ secret('GITGUARDIAN_API_KEY') }}`.

`apiUrl` defaults to the US region `https://api.gitguardian.com`. Use `https://api.eu1.gitguardian.com` for EU workspaces and `https://<instance>/exposed` for self-hosted GitGuardian.

## Tasks

Shared conventions: every list task (`List`) takes `fetchType` (`FETCH`, `FETCH_ONE`, `STORE`, `NONE`), `maxResults` and `perPage`; use `STORE` for large result sets. `ordering` is an enum on the tasks that sort: write `DATE_DESC` or the API form `-date`, in any casing. Write tasks never return secret values, except `honeytokens.Create`, which returns the decoy encrypted.

### Secrets scanning (`scan`)

- `scan.Scan`: scans `content` (named after `filename`) and/or `files` (`kestra://` URIs). Documents are at most 1 MB. Fails when a secret is found unless `failOnPolicyBreak: false`. Scope `scan`.
- `scan.CreateIncidents`: same inputs plus required `sourceUuid`, optional `locationUrl` and `authorEmail`; records the secrets as incidents on a custom source. The endpoint is in beta. Scope `scan:create-incidents`.

### Secret incidents (`incidents`, `publicincidents`)

- `List` (filters: `status`, `severity`, `validity`, `dateAfter`, `dateBefore`, `detectorGroupName`, `assigneeEmail`, `tags`, `riskScoreMin`, `ordering`) and `Get` (`incidentId`).
- Triage tasks, all with `incidentId`: `Assign` (`assigneeEmail` or `assigneeMemberId`, `sendEmail`), `Update` (`severity`, `customTags`), `AddNote` (`comment`), `Ignore`, `Reopen`, `Resolve`.
- `publicincidents` mirrors `incidents` for the Public Monitoring perimeter. Its IDs are not interchangeable with internal incident IDs, `Ignore` and `Resolve` take comma-separated reason lists (`ignoreReasons`, `resolveReasons`), and `Update` makes separate calls for severity and custom tags.
- Scopes `incidents:read` for reads, `incidents:write` for triage.

### Webhooks (`webhooks`)

- `webhooks.Receive`: verifies the HMAC-SHA256 signature of a GitGuardian custom webhook delivered through the core `Webhook` trigger (`body`, `headers`, `signatureToken`, `maxClockSkew`, `failOnInvalidSignature`). Kestra hands the body parsed, so verification tries Python `json.dumps` formatting and compact JSON; set `rawBody` for a strict check. No scope.

### Sources (`sources`)

- `List` (`search`, `sourceType`, `health`, `visibility`, `sourceCriticality`, `monitoringStatuses`, `teamId`, `ordering`), `Get` (`sourceId`), `Scan` (`sourceIds`, starts a historical scan, beta), `CreateCustomSource` (`name`, `sourceDescription`). Scopes `sources:read`, `sources:scan`, `sources:write`.

### Honeytokens (`honeytokens`)

- `Create` (`name`, `honeytokenDescription`, `honeytokenType`, `customTags`): the value comes back in `encryptedToken` and the task fails before calling the API when `kestra.encryption.secret-key` is not configured, so no orphan decoy is left behind.
- `List` (`status` enum, `honeytokenType`, `search`, `tags`, `ordering`), `Get`, `Reset` (only after the honeytoken triggered), `Revoke`, all by `honeytokenId`. Scopes `honeytokens:read`, `honeytokens:write`.

### Audit logs, health checks, teams and members

- `auditlogs.List`: filters `eventName`, `memberEmail`, `memberId`, `tokenId`, `ipAddress`, `dateAfter`, `dateBefore`. Scope `audit_logs:read`.
- `healthchecks.List` and `healthchecks.Run` (`integrationType`, `instanceId`). Scopes `health_checks:read`, `health_checks:write`.
- `teams.List` and `members.List`: read-only lookups for routing and audits. Scopes `teams:read`, `members:read`.

## Triggers

Every trigger authenticates like the tasks, polls at `interval` (default `PT5M`), starts one execution per poll and delivers at most `maxItemsPerPoll` items (default 100, maximum 1000), oldest first; the rest fire on the next polls. State lives in the flow namespace KV store and is seeded at the first poll, so only new items fire.

- `incidents.Trigger` and `publicincidents.Trigger`: new or re-triggered incidents in `trigger.incidents` (filters `status`, `severity`, `validity`, `detectorGroupName`, `riskScoreMin`; `incidents.Trigger` also takes `tags`, `publicincidents.Trigger` also takes `declarativeSecretStatus`). Scope `incidents:read`.
- `honeytokens.Trigger`: new honeytoken events in `trigger.events` and their honeytokens, without values, in `trigger.honeytokens`, with optional `honeytokenId`. Each poll reads one hour behind the newest delivered event and skips delivered IDs, so a use that GitGuardian reports late is still delivered. Scope `honeytokens:read`.
- `auditlogs.Trigger`: new audit log entries in `trigger.events`, optionally filtered by `eventNames`. Scope `audit_logs:read`.
- `healthchecks.Trigger`: integration instances that entered one of `statuses` (default `FAIL`, optionally filtered by `types`) in `trigger.checks`; one fire per failure streak. Scope `health_checks:read`.

## Typical flows

1. **Pre-flight scan**: a flow renders a file or dataset, `scan.Scan` checks it, and the flow fails before publishing if a secret is present.
2. **Incident response**: `incidents.Trigger` starts a flow per poll with the new incidents (`trigger.incidents`, capped by `maxItemsPerPoll`), which loops over them to notify a channel, assigns an owner, opens a ticket, and records a note; a rotation flow ends with `incidents.Resolve` and `secretRevoked: true`.
3. **Real-time alternative**: point a GitGuardian custom webhook at Kestra's webhook endpoint, use the core `Webhook` trigger, and pass `trigger.body` and `trigger.headers` to `webhooks.Receive` for signature verification and a typed `incident`.
4. **Reporting**: `incidents.List` or `auditlogs.List` with `fetchType: STORE` export data for dashboards, SIEMs and compliance.
5. **Non-VCS data**: `sources.CreateCustomSource` once, then `scan.CreateIncidents` on every export to record real incidents for data GitGuardian does not monitor natively.
6. **Tripwires**: `honeytokens.Create` in deployment flows, `honeytokens.Trigger` into the incident response flow.
7. **Perimeter health**: `healthchecks.Trigger` when an integration breaks, `sources.Scan` after onboarding repositories.

## Required scopes

| Task | Scope |
|---|---|
| `scan.Scan` | `scan` |
| `incidents.Trigger`, `incidents.List`, `incidents.Get` | `incidents:read` |
| `incidents.Assign`, `incidents.Update`, `incidents.AddNote`, `incidents.Ignore`, `incidents.Reopen`, `incidents.Resolve` | `incidents:write` |
| `publicincidents.Trigger`, `publicincidents.List`, `publicincidents.Get` | `incidents:read` |
| `publicincidents.Assign`, `Update`, `AddNote`, `Ignore`, `Reopen`, `Resolve` | `incidents:write` |
| `webhooks.Receive` | none |
| `scan.CreateIncidents` | `scan:create-incidents` |
| `sources.List`, `sources.Get` | `sources:read` |
| `sources.Scan` | `sources:scan` |
| `sources.CreateCustomSource` | `sources:write` |
| `honeytokens.Trigger`, `honeytokens.List`, `honeytokens.Get` | `honeytokens:read` |
| `honeytokens.Create`, `honeytokens.Reset`, `honeytokens.Revoke` | `honeytokens:write` |
| `auditlogs.Trigger`, `auditlogs.List` | `audit_logs:read` |
| `healthchecks.Trigger`, `healthchecks.List` | `health_checks:read` |
| `healthchecks.Run` | `health_checks:write` |
| `teams.List` | `teams:read` |
| `members.List` | `members:read` |

## Quotas and rate limits

Only the `scan` scope consumes the workspace API quota: one call per `scan.Scan` request (up to 20 documents) and per `scan.CreateIncidents` request. Other tasks are rate limited per token (for example 1000 requests per minute for a Business plan service account); the plugin retries `429` responses up to three times honoring `Retry-After`.

## Safety

Scanning is stateless on the GitGuardian side, and the plugin never writes matched secret strings to task outputs or logs, only the detector, validity, and match positions.
