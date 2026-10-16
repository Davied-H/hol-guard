"""Extract unchanged main CI command bodies for a disposable reader qualification."""

import os
from pathlib import Path


def body(lines: list[str], name: str) -> str:
    marker = f"      - name: {name}"
    assert lines.count(marker) == 1, name
    start = lines.index(marker) + 1
    while start < len(lines) and lines[start] != "        run: |":
        assert not lines[start].startswith("      - "), name
        start += 1
    assert start < len(lines), name
    result = []
    for line in lines[start + 1 :]:
        if line and not line.startswith("          "):
            break
        result.append(line[10:] if line else "")
    assert result, name
    return "\n".join(result) + "\n"


lines = Path(".github/workflows/ci.yml").read_text().splitlines()
for suffix, name in (
    ("wrapper", "Route workspace crates through the compiler cache"),
    ("validate", "Validate the locked Rust workspace"),
):
    script = body(lines, name).replace("${SCCACHE_MODE}", "READ_ONLY")
    Path(os.environ["RUNNER_TEMP"], f"runtime-reader-{suffix}.sh").write_text(script)
