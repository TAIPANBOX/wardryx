# Compatibility

`TAIPANBOX/wardryx` promises the surface below from its 1.0 (`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). A frozen name is not removed or renamed within a major; an additive thing may appear as a minor; an experimental thing may change in any release.

Status: frozen at 1.0.0 (2026-09-13): the surface below is the promise of this major; the gate has held it since the manifest was written ahead of the tag

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
- the approval token's default (single-use or reusable for its TTL) is a configuration default, not wire: it may flip by decision, and WARDRYX_APPROVAL_SINGLE_USE stays the switch either way

## Experimental

- OTLP span export (WARDRYX_OTLP_ENDPOINT): the span attribute names
- replay's candidate-policy mode (replay -policy <candidate>): its report shape

## Support

The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.
