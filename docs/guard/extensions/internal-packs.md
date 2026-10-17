# Internal extension pack format

The offline `guard-command-source compile-packs` operation generates immutable
policy objects from the existing command and MCP sources and reviewed trust
bindings. It does not enable extensions or admit filesystem policy for execution.
Contributor schemas, public records, portable fixtures and commands are unchanged.

The input starts with `HGPS` and byte `01`. Each frame is a four-byte big-endian
length followed by that many bytes. A bounded header declares
`guard.command-pack-source-stream.v1` and the source count. Each source has one
metadata frame (`kind` and its single-extension trust map), then one original
source frame. The native strict decoder sees duplicates and depth before
normalization. Early EOF, surplus frames, unknown fields, missing trust, duplicate
IDs, invalid ownership, dependency cycles and missing relationships fail the build.
Global MCP endpoint/package/alias ownership and the complete native compatibility
inventory remain mandatory. Global checks run before object output.

Each pack owns one extension. Its bounded program is checked by the existing
native admission logic with the globally validated extension/permission interface.
Other extensions' matcher payloads are not copied into dependency packs. Global
relationships do not relax the per-source, per-program or matcher budgets.
Partial compatibility inventory validation is available only inside the offline
compiler; ordinary runtime program admission still requires the complete inventory.

Output is newline-delimited object records followed by one release root record.
Object records contain SHA-256, exact byte length and base64 data. Stored objects
are uncompressed and at most 64 KiB. Larger JSON values use bounded concatenation
trees; an assembled value is at most 8 MiB. Matcher nodes retain their existing
content identity and are stored independently so packs can share them. The program
skeleton, catalog metadata and public descriptors have separate references.

A pack manifest binds its extension ID, source digest, trust digest, native program
digest, engine implementation, semantic profile and related source interfaces.
An internal build key covers the validated source/trust input, conservative engine
identity, semantic profile and related interfaces. It does not replace public
contribution identity or grant authority to cached output.

The release root commits to a complete hash-trie index. Leaves contain at most
64 sorted unique entries; branches contain at most 16 non-overlapping SHA-256
prefixes. Adding a source changes its path rather than shifting subsequent pages.
Lookup verifies object length/digest, prefix routing, ordering and declared counts
on its path. Missing or corrupt data returns an error. The fixed format budgets
are recorded in `contracts/catalog-delivery/packs.v1.json`.

`scripts/build_native_command_packs.py` stages these outputs. It verifies emitted
object bytes, rejects poisoned cached objects, and atomically replaces the root
only after successful compiler completion. Interrupted builds may leave
unreferenced immutable objects. The current compiler still revalidates every
source; storage reuse is not compilation-cache qualification.

Integrity is not publisher authority. A root must be bound to an authenticated
release before runtime use; an arbitrary directory or a matching hash alone is
insufficient. This offline format does not add a downloader or activation path.
The legacy aggregate compiler, release packaging and contribution commands remain
available while their consumers migrate.
