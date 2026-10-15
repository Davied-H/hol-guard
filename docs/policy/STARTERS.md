# Starter policies

`hol-guard policy init --starter <name>` writes a starter policy to `guard-policy.yaml`. Each starter
carries the editor modeline and two example tests, so `hol-guard policy test guard-policy.yaml` passes on
a fresh file.

The starters match the starter gallery in Policy Studio, so a policy you begin in the browser and one you
begin on the command line read the same. Names are the same in both places.

| Starter | What it does |
| --- | --- |
| `safe-defaults` | Blocks installs from unknown publishers and asks before agents touch secrets. This is the default. |
| `package-firewall` | Blocks known compromised packages and holds anything from a new publisher for review. |
| `secrets-guard` | Asks before an agent reads environment variables or files into a prompt. |
| `mcp-guard` | Asks before an agent connects to an MCP server, so new servers never start silently. |
| `team-baseline` | A shared floor for every device: compromised packages and secret reads are blocked outright. |
| `blank` | No rules. Guard asks at the device and you add rules as you learn what your agents do. |

List them any time with `hol-guard policy init --list`.

## Keeping the two in step

The CLI starters live in `src/codex_plugin_scanner/guard/policy_starters.py`. When a starter is added,
renamed or changed in Policy Studio, change the matching entry there and update the table above. The
parity tests render every starter and run its example tests, so a starter whose examples drift from its
rules fails the build.
