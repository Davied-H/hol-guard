# Fleet posture

When a machine is connected to Guard Cloud, Guard reports a small, structured summary of that machine so
Cloud can show which AI tools are protected, which need setup, and which policy each machine has applied.
The contract is [`fleet-posture/v1`](../../contracts/fleet-posture/v1/README.md). Local protection never
depends on it: if reporting is off, offline or rejected, interception, blocking and receipts work exactly
as before.

## What Guard reports

| Section | Contents |
| --- | --- |
| `client` | Guard version, release channel (`stable` or `alpha`), runtime, and auto-update status. |
| `machine` | OS name, OS version, CPU architecture, and a SHA-256 hash of the host name. |
| `aiTools` | One row per supported AI tool: tool version when known, setup status, protection state, hook coverage, blind spots, posture override, artifact count, last activity, and an inventory digest. |
| `inventory` | Installed skills, plugins, MCP servers and similar items, as full, delta or digest-only (see below). |
| `policy` | Applied bundle version and hash, applied policy version number, status (`applied`, `validated`, `rejected` or `none`), error code and apply time. |

Guard does not send file contents, prompts, command lines, environment values, user names or raw paths.
Item locations are sent as a SHA-256 hash of the config path.

## Protection state

Each AI tool gets one `protectionState`:

| State | When |
| --- | --- |
| `protected` | Guard setup for the tool is active. |
| `broken` | Setup is partial or broken: hooks or config exist but do not work. |
| `needs_setup` | The tool is installed (its config is on disk) but Guard is not set up for it. |
| `paused` | Protection for the tool is turned off in Guard (the `watch` posture). |
| `stale` | The tool was detected before, but nothing has been seen for 7 days. |
| `not_detected` | The tool is not installed on this machine. |

## Inventory modes and size limit

- **full**: every installed item. Sent on the first report, after Guard Cloud asks for one, after
  `hol-guard inventory --sync`, and at least every 7 days.
- **delta**: only items added or changed since the last accepted report, plus `removed` entries.
- **digest_only**: no item rows, only the inventory digest. Used when reporting is minimal (below) or when
  not even one item fits in a request.

A request carries at most 250 items and 65,536 bytes. A larger inventory streams over several syncs as
delta chunks, each chunk as large as fits. Guard only records a report as sent after Guard Cloud accepts
the request, so a failed sync repeats the same changes next time.

### Digest

The inventory digest is `sha256:` plus the hex SHA-256 of the item rows sorted lexicographically and
serialized as compact JSON (`separators=(",", ":")`). Each row is the list
`[kind, name, version, hash, harness]` with `null` written as an empty string. Per-tool digests use the
same rows restricted to one harness. Cloud compares digests to detect drift without receiving every row.

## Turning reporting down

```bash
hol-guard settings set fleet-posture off
hol-guard settings set fleet-posture on
```

With `off`, Guard still reports its version, each tool's protection state and the policy status, which
Cloud needs to show whether a machine is protected. It stops sending the OS version, blind-spot detail and
per-item inventory, and sends `digest_only`. Turn it back on to resume full reporting.

Installs managed by an organization (MDM-installed Guard) cannot opt out. `settings set fleet-posture off`
exits with status 2 and explains why, and `hol-guard cloud status` shows the install as managed.

## Seeing what is reported

```bash
hol-guard cloud status [--json] [--offline]
```

Prints the last sync time, a summary of the last report Guard sent, and what Guard Cloud currently shows for
this machine (`GET /api/guard/v1/fleet/machines/self`). If you are signed out, offline, or Guard Cloud does
not offer that route yet, the command still succeeds and prints a plain message. `--offline` skips the
Cloud lookup.

```bash
hol-guard inventory --json --sync
```

Prints the local inventory and queues a full inventory for the next sync.

## Policy acknowledgement

The posture's `policy` section and the existing policy acknowledgement describe the bundle applied on the
machine. A bundle applied during a sync cycle used to reach Cloud one sync interval later. Guard now
sends one extra, receipt-free request in the same cycle with the new acknowledgement. It sends that
follow-up at most once per bundle hash and records the attempt before sending, so a failure never loops.

Bundles whose version is a legacy string rather than an integer are reported with
`appliedBundleVersion: null`; the bundle hash still identifies them.

## Known gaps

- The native runtime does not assemble sync context; the Python runner does, so the posture is built in
  Python. The native sync transport identifies itself as `hol-guard-native/<version>`.
- `postureOverride` reports `default` when no override is set, `off` for the `watch` posture and
  `enforce` otherwise. `observe` is part of the contract but Guard does not emit it.
