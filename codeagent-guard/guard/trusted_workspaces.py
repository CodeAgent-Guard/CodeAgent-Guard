from __future__ import annotations

import json
import threading
from pathlib import Path


class TrustedWorkspaceStore:
    """Persistent user-selected filesystem roots."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._roots = self._load()

    def _load(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        roots = payload.get("roots", []) if isinstance(payload, dict) else []
        return list(dict.fromkeys(
            str(root).strip() for root in roots if str(root).strip()
        ))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"roots": self._roots}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def roots(self) -> tuple[Path, ...]:
        with self._lock:
            return tuple(Path(root) for root in self._roots)

    def add(self, path: Path) -> None:
        value = str(path)
        with self._lock:
            if not any(root.casefold() == value.casefold() for root in self._roots):
                self._roots.append(value)
                self._save()

    def remove(self, path: Path) -> bool:
        value = str(path)
        with self._lock:
            matching = next(
                (
                    root for root in self._roots
                    if root.casefold() == value.casefold()
                ),
                None,
            )
            if matching is None:
                return False
            self._roots.remove(matching)
            self._save()
            return True
