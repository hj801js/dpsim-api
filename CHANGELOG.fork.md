# hj801js/dpsim-api — Changelog

Delta from upstream `sogno-platform/dpsim-api@main` (as of 2026-04-17).

## Environment-configurable service URLs

`REDIS_URL` and `FILE_SERVICE_URL` were hard-coded to Kubernetes service
hostnames (`redis-master`, `sogno-file-service`). On any non-k8s
environment (developer laptop, Docker Compose, CI) the API bound to
non-existent hosts and failed to start. Both are now overridable via
environment variables; the k8s defaults remain.

Branch: `fix/configurable-service-urls`.

## AMQP payload hardcoding removal

The `executable` and `name` fields of the AMQP message were overwritten
with fixed strings (`/usr/bin/dpsim-worker` and a constant sim name)
regardless of what the REST client supplied, which meant custom workers
could not distinguish the invocation contract. `simulation_type` also
wasn't propagated, so the worker had to guess. All three are now
pass-through from the POST body.

Downstream workers that *relied* on the overwrite must now extract
these fields from their own configuration rather than from the AMQP
payload. The companion worker in `hj801js/dpsim` service-stack already
matches the new contract.

Branch: `fix/amqp-payload-hardcoded`.

---

Contact: Jimmy Kim · jimmykim07@gmail.com · `hj801js`
