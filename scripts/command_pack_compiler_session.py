"""Process-local native compilation reuse; accepts no serialized cache input."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from contextlib import ExitStack, suppress
from pathlib import Path


class PackCompilerSession:
    """Own one compiler process and discard every cached value on close."""

    def __init__(self, compiler: Path):
        self.compiler = compiler.resolve()
        self.resources = ExitStack()
        self.errors = self.resources.enter_context(tempfile.TemporaryFile())  # noqa: SIM115 - owned by ExitStack
        self.closed = False
        try:
            self.process = subprocess.Popen(
                [str(self.compiler), "compile-packs-session"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.errors,
            )
        except BaseException:
            self.resources.close()
            raise

    def submit(self, compiler: Path, source):
        if self.closed or compiler.resolve() != self.compiler or self.process.poll() is not None:
            raise ValueError("native compiler session is unavailable or differs")
        source.seek(0, 2)
        length = source.tell()
        source.seek(0)
        assert self.process.stdin is not None
        self.process.stdin.write(length.to_bytes(8, "big"))
        shutil.copyfileobj(source, self.process.stdin, length=64 * 1024)
        self.process.stdin.flush()
        return self.process

    def error(self) -> str:
        self.errors.seek(0)
        return self.errors.read(2048).decode(errors="replace")

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.stdin is not None:
            with suppress(BrokenPipeError):
                self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()
        self.resources.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
