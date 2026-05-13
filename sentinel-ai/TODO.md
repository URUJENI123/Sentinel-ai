# Sentinel AI - TODO

## Goal
Prevent Sentinel from crashing when Redis is unreachable by adding a degraded mode to the ingestion pipeline.

## Steps
- [x] Update `ingestion/pipeline.py`:
  - [x] Change `_connect_redis()` to set a degraded flag instead of raising RuntimeError when Redis cannot be reached.
  - [x] Ensure `start()` still completes even if Redis is unavailable.
  - [x] Make `_publish_metrics()` and `_enqueue_event()` safe when `_redis` is None.
  - [x] Improve `stream_events()` error messaging when Redis isn’t connected.

- [ ] Run unit tests (at least ingestion-related) to confirm behavior.
- [ ] Re-run the `detect` command to confirm the crash is resolved.

