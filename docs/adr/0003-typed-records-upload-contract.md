# 0003. Upload typed records over a contract owned by Enigma-Publisher

Status: Accepted

Date: 2026-11-17 (backfilled)

## Context

The sensor's logs are consumed by Enigma-Publisher and Enigma-Subscriber, and imitated by
Enigma-Data-Generator. Sensors in the field update only when reinstalled, so old versions keep
sending for a long time after a release. The upload format therefore has to be shared exactly
between repositories, stay compatible across versions, and fit in the memory of a customer host.

## Decision

- The sensor calls `SensorIngest.uploadRecords` over gRPC (Google Remote Procedure Call) with TLS
  (Transport Layer Security), defined in `internal/api/ingest/sensor_records.proto`. That file is a
  byte-identical copy of the Enigma-Publisher one, and `.github/workflows/proto-drift.yml` fails
  CI (continuous integration) when they differ.
- `internal/records/records.go` maps Zeek JSON (JavaScript Object Notation) lines into typed records by field name. A column
  with no proto field is dropped; a record that cannot be read is skipped and counted.
- Records are streamed into zlib-compressed `RecordBatch` payloads (`COMPRESSION_ZLIB`), so memory
  holds one compressed batch. Batches stay under `enigma_api.max_payload_size_mb` (capped at
  `maxBatchBytes`, 96 MiB) and `maxRecordsPerUpload` (1,000,000) in `internal/api/client.go`.
- Each request carries `schemaVersion` (`records.SchemaVersion`), `sensorVersion`, per-log counts
  and the metadata map from `internal/metadata/collector.go`.
- Old `.bin` buffer files from sensors before typed uploads are still sent through
  `uploadExcelMethod` (`internal/api/publish/`), so an upgrade loses nothing buffered.

## Consequences

- Change the Publisher's proto first, copy it here, then regenerate the Go code (see
  `DEVELOPMENT.md`). Follow the compatibility rules at the top of `sensor_records.proto`: adding
  an optional field is safe; adding a log type, renaming, retyping or removing a field is not.
- A contract change touches the Publisher, Subscriber and Data-Generator, and the backend must keep
  accepting the old shape while old sensors remain.
- A newer Zeek that adds columns does not break ingest, but a new column is not uploaded until it
  is added to the schema.
- Do not remove the legacy `publish` path while sensors that buffered `.bin` files may still
  upgrade.
