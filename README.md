# ghost-telemetry-check

A free, customer-run security self-check that answers one question: **does
your SIEM ingestion endpoint accept events from unauthenticated senders?**

It uses the same canary methodology as Brava's research: the tool injects a
single semantically inert marker event (`BRAVA-CHECK-<uuid>`) without
credentials. If the endpoint accepts it, anyone who can reach that port can
forge logs in your SIEM. The canary is yours — generated fresh on your
machine, marked, and (where the product API allows) deleted automatically.

Zero telemetry: **ghost-telemetry-check makes no call to Brava or any third party.**
The only network calls go to the endpoints *you* declare with `--target`.
The single, disclosed exception is the optional `--shodan` module, which is
default-off (see [Optional modules](#optional-modules)).

## The two-vantage runbook

Whether an unauthenticated event actually lands is best measured from two
places. Run both; each is a single static binary.

1. **`probe` — outside the perimeter** (cloud VM, home network, anywhere
   that is *not* your SIEM's network). Injects the canary and grades the
   endpoint's answer:

   ```console
   $ ghost-telemetry-check probe --target siem.example.com:8088
   canary marker: BRAVA-CHECK-f5067650-7d2f-44c1-873b-3b970d47b88d (pass to 'ghost-telemetry-check agent --marker' to verify and purge)
   STATUS  CHECK  EVIDENCE  REMEDIATION
   ...
   ```

   Probe prints the canary marker on every run — you need it for step 2.
   Text mode prints it on the `canary marker:` line; under `--json` it rides
   in the report envelope's `canary_marker` field.

2. **`agent` — inside the perimeter** (a host with access to the SIEM's
   product API). Verifies whether the marker actually landed and purges it
   where the product API allows:

   ```console
   $ ghost-telemetry-check agent --target siem.example.com:9200 \
       --marker BRAVA-CHECK-f5067650-7d2f-44c1-873b-3b970d47b88d
   ```

   A `PASS` row means the marker was found and deleted (or never landed);
   a `FAIL` row means the marker is present and could not be deleted.

`audit` runs from anywhere and touches nothing on the network (see below).

## Commands

| command | what it does | network calls |
|---|---|---|
| `probe --target URL[,URL…]` | inject the canary unauthenticated, grade acceptance, auto-purge where the product API allows | only your `--target` endpoints |
| `agent --target URL[,URL…] --marker MARKER` | verify the marker via the product API, purge it | only your `--target` endpoints |
| `audit [--config DIR]` | scan local collector configs for known no-auth settings **and** leaked ingest credentials | none |

Common flags: `--json` (machine-readable report), `--verbose`, `--adapter`
(override adapter selection), `--shodan` (optional module, default off).

### Adapter selection

`--target` takes a URL or bare `host:port`; the port picks the adapter:

| port | adapter |
|---|---|
| 8088 | Splunk HEC (`http(s)://host:8088`) |
| 8888 | fluentd `in_http` |
| 9880 | fluent-bit HTTP input |
| 10080 | Cribl Stream HTTP source |
| 9200 | Elasticsearch bulk API |
| 514 | syslog: `tcp://host:514` or `udp://host:514` (scheme required — the port alone is ambiguous) |
| 12201 | GELF/Graylog: `udp://host:12201` (bare `host:12201` defaults to UDP) |

A port outside this map is an **error with a hint**, never a silent guess —
speaking the wrong protocol unauthenticated at a stranger's port is not
something this tool does. `--adapter hec|fluentd|fluentbit|cribl|elastic|syslog-tcp|syslog-udp|gelf`
overrides the map (for nonstandard ports).

### Syslog targets: fire-and-forget

Plain syslog (514) and GELF (12201) have no response to grade, so probe
reports a `WARN` row — the canary was sent unauthenticated, acceptance is
unconfirmed, verification requires agent mode. Since no syslog vendor
exposes a search API to this tool, the honest path is a manual SIEM search
for the marker (the row spells it out, marker included).

### HEC-class ports: manual purge

Some ingest ports (Splunk HEC, fluentd, fluent-bit, Cribl) have no
search/delete API on the data port. If a canary is accepted there, the
finding carries the exact search to run manually
(`manual purge: search BRAVA-CHECK-…`). Elasticsearch targets are
auto-purged (`_delete_by_query`).

## Audit coverage

Shipped today, `audit` detects:

- Splunk `inputs.conf` raw `splunktcp` inputs (`HF-splunk-1`)
- Fluentd `in_http`/`in_forward` source blocks without auth (`HF-fluentd-1`)
- Elasticsearch `xpack.security.enabled: false` (`HF-elastic-1`)
- Fluent Bit `[INPUT]` `Name http` inputs bound to all interfaces — the
  `Host` (1.x) and `Listen` (≥2.0) spellings (`HF-fluentbit-1`)
- leaked ingest credentials on disk — Sumo receiver URLs, Sentinel
  SharedKeys (legacy) and DCR ingestion Entra client secrets, Datadog API
  keys, Chronicle service-account keys (`HF-cloud-*`)

Planned, not yet shipped: tokenless Cribl source configurations, firewall
rules allowing port 514 from `0.0.0.0/0`, GELF server configuration, and
the publish-hash badge. A run today reports no findings for those classes.

## Optional modules

- **`--shodan`** (default off) — checks whether your endpoint's IP is
  already in Shodan's public scan index, i.e. findable by attackers. This
  module sends your endpoint IP to Shodan — the only check that does;
  default off. It requires your own `SHODAN_API_KEY` in the environment and
  aborts loudly (exit 3) if the flag is set but the key is missing. Combine
  it with `probe`, or run it alongside `agent` on a marker you already
  purged for a lookup-only run. Being indexed renders a `WARN` row.
- **Credential scan** — part of `audit`, always local: it reads the files
  under `--config` (default `.`) and flags ingest credentials committed to
  disk (Sumo receiver URLs, Sentinel SharedKeys (legacy) and DCR ingestion
  Entra client secrets, Datadog API keys, Chronicle service-account keys).
  It never makes a network call and never validates a found credential —
  findings are redacted previews with a
  rotate-and-move-to-a-secret-store remediation.

## Exit codes

| code | meaning |
|---|---|
| 0 | all checks pass |
| 1 | warnings present (e.g. unverifiable syslog canary, Shodan-indexed endpoint) |
| 2 | failures present (canary accepted, leaked credential, unhardened config) |
| 3 | internal or usage error — including unreachable endpoints |

An unreachable endpoint exits 3, never 0: "could not test it" is not
"secure". With `--json`, a clean run emits one JSON object; on exit 3,
`error:` diagnostic lines precede the report, so treat any nonzero exit
with diagnostics as a failed run.

## Building

```console
$ ./scripts/build.sh          # darwin/linux × arm64/amd64, CGO_ENABLED=0, stripped
$ shasum -a 256 dist/*        # checksums print at the end of the build
```

Binaries land in `dist/` (gitignored). Go 1.24+, stdlib only — no
dependencies, no cgo, static by construction.
