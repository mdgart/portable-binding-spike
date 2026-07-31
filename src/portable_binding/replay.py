"""Atomic replay protection used at the trusted execution boundary."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Protocol


class ReplayError(RuntimeError):
    """Raised when a certificate nonce was already consumed."""


class ReplayLedger(Protocol):
    def reserve(self, nonce: str) -> None: ...


class MemoryReplayLedger:
    def __init__(self) -> None:
        self._nonces: set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, nonce: str) -> None:
        with self._lock:
            if nonce in self._nonces:
                raise ReplayError(f"nonce already consumed: {nonce}")
            self._nonces.add(nonce)


class SQLiteReplayLedger:
    """Persistent nonce ledger for CLI/custom-job demonstrations."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_nonce "
                "(nonce TEXT PRIMARY KEY, consumed_at TEXT DEFAULT CURRENT_TIMESTAMP)"
            )

    def reserve(self, nonce: str) -> None:
        try:
            with sqlite3.connect(self.path) as connection:
                connection.execute(
                    "INSERT INTO consumed_nonce(nonce) VALUES (?)",
                    (nonce,),
                )
        except sqlite3.IntegrityError as error:
            raise ReplayError(f"nonce already consumed: {nonce}") from error

