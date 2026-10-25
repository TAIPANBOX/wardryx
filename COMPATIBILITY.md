# Compatibility

`TAIPANBOX/wardryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: frozen at 1.0.0 (2026-09-13), carried unchanged into 2.0.0 (2026-10-18), into 2.1.0 (2026-10-18), into 2.2.0 (2026-10-18), into 2.2.1 (2026-10-19), into 2.3.0 (2026-10-19), into 2.4.0 (2026-10-19) and into 2.4.1 (2026-10-26): the surface below is the promise of this major; no frozen name was removed or renamed in 2.0.0, 2.1.0, 2.2.0, 2.2.1, 2.3.0, 2.4.0 or 2.4.1, its additions in 2.1.0, 2.2.0, 2.3.0 and 2.4.0 are listed under additive, and its behaviour changes are in docs/releases/v2.0.0.md, docs/releases/v2.1.0.md, docs/releases/v2.2.0.md, docs/releases/v2.2.1.md, docs/releases/v2.3.0.md, docs/releases/v2.4.0.md and docs/releases/v2.4.1.md. The gate has held it since the manifest was written ahead of the tag

## Frozen

### agentevent.emitted (8)

- `policy_allow`
- `policy_deny`
- `approval_requested`
- `approval_granted`
- `approval_denied`
- `approval_timeout`
- `approval_unanswered`
- `policy_updated`
- held in: `internal/api/api.go`

### cli.subcommands (5)

- `serve`
- `check`
- `approvals`
- `replay`
- `version`
- held in: `cmd/wardryx/main.go`

### decide.decisions (3)

- `allow`
- `deny`
- `hold`
- held in: `internal/pdp/pdp.go`

### decide.request (11)

- `agent_id`
- `run_id`
- `on_behalf_of`
- `tool_names`
- `domains`
- `steps`
- `model`
- `est_cost_usd`
- `attestation_method`
- `approval_token`
- `chain_proven`
- held in: `internal/api/api.go`

### decide.response (6)

- `decision`
- `policy_version`
- `reason`
- `approval_id`
- `approval_token_required`
- `cacheable`
- held in: `internal/api/api.go`

### env (11)

- `WARDRYX_ADDR`
- `WARDRYX_KEYS`
- `WARDRYX_ALLOW_DEVKEY`
- `WARDRYX_DB`
- `WARDRYX_POLICY`
- `WARDRYX_EVENTS_PATH`
- `WARDRYX_POLICY_ARCHIVE`
- `WARDRYX_APPROVAL_SECRET`
- `WARDRYX_APPROVAL_SINGLE_USE`
- `WARDRYX_APPROVAL_UNANSWERED_AFTER`
- `WARDRYX_OTLP_ENDPOINT`
- held in: `internal/config/config.go`

### http.routes (9)

- `GET /healthz`
- `POST /v1/decide`
- `POST /v1/approvals/{id}/decide`
- `GET /v1/approvals`
- `GET /v1/status`
- `GET /v1/policies`
- `GET /v1/policies/{id}`
- `PUT /v1/policies/{id}`
- `DELETE /v1/policies/{id}`
- held in: `internal/api/api.go`

### policy.fields (11)

- `name`
- `target`
- `deny_tool`
- `allow_domains`
- `require_human_above_usd`
- `deny_above_usd`
- `max_steps`
- `deny_if_unattested`
- `deny_if_chain_unproven`
- `max_chain_depth`
- `require_root_principal`
- held in: `internal/policy/policy.go`

## Additive within a major

- new event types under source wardryx (agent-passport SPEC 6.2 allows them within a source)
- new policy fields, each with a zero value that means 'no restriction'
- new routes and new optional request fields on /v1/decide
- identity_source, an optional request field on /v1/decide: absent or unknown is none, so a caller that sends nothing is decided as before; additive, so a minor release
- require_identity_source, a new policy field whose absent value means no requirement; additive, so a minor release
- the approval token's default (single-use or reusable for its TTL) is a configuration default, not wire: it may flip by decision, and WARDRYX_APPROVAL_SINGLE_USE stays the switch either way
- WARDRYX_APPROVER_JWKS, an optional environment variable: unset, no approval statement is accepted and every decision is recorded as the key that made it, as before; set, the console keys in the file verify the approval statements a person's decision carries, and the file must read or serve refuses to start; additive, so a minor release
- approver_statement, an optional request field on /v1/approvals/{id}/decide, and approver_kind on the approval listing and the approval_granted and approval_denied events: with a verified statement decided_by names the approver (approver:<id>) and approver_kind is person; with WARDRYX_APPROVER_JWKS set and no statement a decision is refused with 403 approver_statement_required and the hold stays pending, unless WARDRYX_ALLOW_KEY_APPROVALS=1; with no key set a decision with no statement is recorded as the key, as before; additive, so a minor release
- WARDRYX_ALLOW_KEY_APPROVALS, an optional environment variable: set to exactly 1, a key-kind approval is accepted while WARDRYX_APPROVER_JWKS is set, and is logged each time; unset or any other value, the decision is refused as above; additive, so a minor release
- WARDRYX_RECORD_FAILMODE, an optional environment variable: unset is closed, which refuses an allow or a hold whose record was not written (503 record_unavailable), and open returns it and flags /readyz; a configuration default, not wire, so the default may flip by decision (invariant 40), and the variable stays the switch either way
- approval tokens signed by Keyryx, an optional mode: with WARDRYX_APPROVAL_SIGNER=keyryx a grant mints an ES256 compact JWS whose header names the kid that signed it, and the token verifies from the key set wardryx caches; the HMAC token of earlier grants stays the default and verifies until WARDRYX_APPROVAL_V2_UNTIL. The token's format is not wire: the approval_token field and its place on /v1/decide are unchanged, and a caller treats the token as an opaque string
- WARDRYX_APPROVAL_SIGNER, WARDRYX_KEYRYX_URL, WARDRYX_KEYRYX_CREDENTIAL_FILE and WARDRYX_APPROVAL_V2_UNTIL, optional environment variables: unset, each keeps the 2.1.0 behaviour; configuration choices, not wire
- agent token verification, optional: with WARDRYX_AGENT_TOKEN_ISSUER set, /v1/decide verifies a token sent in the optional request field agent_token and the DPoP proof sent in the optional request field agent_dpop_proof; a caller that sends neither and claims no agent-token source is decided as before. With the issuer unset, a token is ignored and the request decides as 2.2.1 did
- WARDRYX_AGENT_TOKEN_ISSUER, WARDRYX_AGENT_TOKEN_JWKS_URL, WARDRYX_AGENT_TOKEN_JWKS_FILE, WARDRYX_AGENT_TOKEN_AUDIENCES, WARDRYX_AGENT_TOKEN_REVOCATION_URL, WARDRYX_AGENT_TOKEN_DOOR_ORIGINS, WARDRYX_AGENT_TOKEN_REQUIRE_PROOF and WARDRYX_AGENT_TOKEN_PROOF_MAX_AGE_SECONDS, optional environment variables: with the issuer and every other name unset, the check is off; a name set without the issuer refuses to start; configuration choices, not wire
- new refusals on /v1/decide, 403 with agent_contradicts_token, agent_token_invalid, agent_token_required, agent_token_proof_required or agent_token_proof_invalid, each arising only with WARDRYX_AGENT_TOKEN_ISSUER set; a verified token naming another agent also writes an identity_mismatch event under source wardryx. The reason strings are the response, not wire fields, and a caller that does not send a token is refused only when it claims the agent-token source

## Experimental

- OTLP span export (WARDRYX_OTLP_ENDPOINT): the span attribute names
- replay's candidate-policy mode (replay -policy <candidate>): its report shape
- POST /v1/filter-tools: no enforcement point acts on its answer yet

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
