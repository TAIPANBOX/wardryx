# testdata

`verdryx-events.ndjson` is a file the quality plane wrote itself, on a real run, so
that the tests read Python's JSON and Python's chain hash with Go's reader and the
shared library's chain check.

It was made with verdryx at `452ac7c` (main after #59) and rfc8785 0.1.4, over a
generated trace of three agents (two with a spent budget, one healthy):

    verdryx slo --input runs.ndjson --events verdryx-events.ndjson

where `runs.ndjson` holds one record per run
(`outcome`, `cost_usd`, `run_id`, `agent_id`, `key_id`, `calls`, `refused_calls`,
`last_ts_millis`). Two agents fell below their objective with the interval showing
it, so two `slo_burn` events with `trigger: exhausted` were written, the second
chained to the first by `prev_hash`.
