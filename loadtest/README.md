# Sensor Load Test

A Docker Compose setup that generates HTTP (Hypertext Transfer Protocol) and DNS (Domain Name
System) traffic on the host while the sensor captures it, then summarises container resource use and capture output.

**It does not currently run.** Known problems:

- `.dockerignore` excludes `bin/` and `loadtest/`, so `Dockerfile.sensor` cannot copy the sensor
  binary or its config and the sensor image fails to build.
- `configs/sensor-config.json` keeps the placeholder `network_id`, which the sensor rejects at
  startup. It also sets `load_test` and `zeek.path`, which the sensor ignores.
- The sensor container writes captures to `loadtest/captures/`, but the script counts files in
  `../captures/`.
- `Dockerfile.sensor` installs Zeek from the OpenSUSE repository rather than the bundled packages
  the real Docker image uses.

No performance figures from this harness are current.

## Pieces

| File | Purpose |
| --- | --- |
| `run-load-test.sh` | Runs a test and writes results to `results/<timestamp>/` |
| `docker-compose.yml` | `sensor` (privileged, host network), `http-load` (curl), `dns-load` (dig against 8.8.8.8), `target-server` (nginx) |
| `Dockerfile.sensor` | Sensor image for the test, using a prebuilt `bin/enigma-sensor` |
| `configs/sensor-config.json` | Sensor config: one 60 second capture window, upload off |

## Intended usage

Build the sensor first, then run from this directory:

```sh
go build -o bin/enigma-sensor ./cmd/enigma-sensor   # from the repository root
cd loadtest
./run-load-test.sh quick         # 60 s, 2 HTTP and 2 DNS generators
./run-load-test.sh performance   # 120 s, 8 HTTP and 8 DNS generators
```

| Variable | `quick` default | `performance` default | Meaning |
| --- | --- | --- | --- |
| `HTTP_RPS` | 50 | 200 | Requests per second per HTTP generator |
| `DNS_QPS` | 100 | 400 | Queries per second per DNS generator |
| `TEST_DURATION` | 60 | 120 | Seconds |
| `HTTP_GENERATORS` | 2 | 8 | HTTP generator containers |
| `DNS_GENERATORS` | 2 | 8 | DNS generator containers |

The DNS generators query 8.8.8.8, so the test sends real traffic to the internet.

Results: `test.log`, `logs.txt` (all container logs), `LOAD_TEST_SUMMARY.md`, plus `stats.log`
in `quick` mode or `docker_performance_stats.csv` and `system_performance.csv` in `performance`
mode.
