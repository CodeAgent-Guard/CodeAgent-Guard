from __future__ import annotations

import email.message
import os
import re
import shutil
import smtplib
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Callable

try:
    import resource
except ImportError:  # Windows development host
    resource = None


class ToolExecutorRegistry:
    """Concrete tool implementations, independent from policy and Agent."""

    def __init__(
        self,
        workspace: Path,
        outbox: Path,
        open_directory_roots: list[Path] | tuple[Path, ...] | None = None,
        external_write_roots: list[Path] | tuple[Path, ...] | None = None,
        trusted_workspace_roots: list[Path] | tuple[Path, ...] | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.open_directory_roots = tuple(
            Path(path).resolve(strict=False)
            for path in (open_directory_roots or ())
        )
        self.external_write_roots = tuple(
            Path(path).resolve(strict=False)
            for path in (external_write_roots or ())
        )
        self.trusted_workspace_roots = tuple(
            Path(path).resolve(strict=False)
            for path in (trusted_workspace_roots or ())
        )
        self.outbox = outbox
        self.outbox.mkdir(parents=True, exist_ok=True)
        self._handlers: dict[str, Callable[[dict], dict]] = {
            "read_file": self.read_file,
            "write_file": self.write_file,
            "run_command": self.run_command,
            "http_request": self.http_request,
            "send_email": self.send_email,
            "list_directory": self.list_directory,
            "open_directory": self.open_directory,
            "search_files": self.search_files,
            "make_directory": self.make_directory,
            "delete_path": self.delete_path,
            "move_path": self.move_path,
        }

    def execute(self, tool: str, args: dict) -> dict:
        handler = self._handlers.get(tool)
        if handler is None:
            raise ValueError(f"未注册的工具执行器: {tool}")
        return handler(args)

    def register(self, name: str, handler: Callable[[dict], dict]) -> None:
        self._handlers[name] = handler

    def _authorized_roots(self) -> tuple[Path, ...]:
        return (
            self.workspace,
            *self.trusted_workspace_roots,
            *self.external_write_roots,
        )

    def set_trusted_workspace_roots(
        self,
        roots: list[Path] | tuple[Path, ...],
    ) -> None:
        self.trusted_workspace_roots = tuple(
            Path(path).resolve(strict=False) for path in roots
        )

    def _resolve_authorized_path(
        self,
        raw_path: str,
        *,
        tool: str,
    ) -> tuple[Path, Path]:
        path = Path(raw_path)
        if not path.is_absolute():
            path = self.workspace / path
        path = path.resolve(strict=False)
        root = self._authorized_root(path, self._authorized_roots())
        if root is None:
            raise PermissionError(f"路径未在 {tool} 授权范围内: {path}")
        return path, root

    def read_file(self, args: dict) -> dict:
        path, _ = self._resolve_authorized_path(
            args["path"],
            tool="read_file",
        )
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"文件不存在: {path}")
        if path.stat().st_size > 1_000_000:
            raise ValueError("文件超过 1 MB 读取上限")
        return {"path": str(path), "content": path.read_text(encoding="utf-8", errors="replace")}

    def write_file(self, args: dict) -> dict:
        path, root = self._resolve_authorized_path(
            args["path"],
            tool="write_file",
        )
        if (
            root in (*self.trusted_workspace_roots, *self.external_write_roots)
            and path == root
        ):
            raise PermissionError("不能直接写入外部授权根目录本身")
        if path.exists() and path.is_dir():
            raise IsADirectoryError(f"目标是目录，不能作为文件写入: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        content = str(args.get("content", ""))
        path.write_text(content, encoding="utf-8")
        return {"path": str(path), "bytes": len(content.encode())}

    def run_command(self, args: dict) -> dict:
        command = str(args["cmd"])
        timeout = max(1, min(int(args.get("timeout", 10)), 30))
        completed = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            cwd=self.workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "HOME": str(self.workspace / ".agent-home")},
            preexec_fn=self._limit_process if resource is not None else None,
        )
        return {
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-20_000:],
            "stderr": completed.stderr[-20_000:],
        }

    @staticmethod
    def _limit_process() -> None:
        """Apply Linux resource limits; this is defense-in-depth, not a container."""
        if resource is None:
            return
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10_000_000, 10_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(
            resource.RLIMIT_AS,
            (512 * 1024 * 1024, 512 * 1024 * 1024),
        )

    def http_request(self, args: dict) -> dict:
        method = str(args.get("method", "GET")).upper()
        body = args.get("body")
        data = None if body is None else str(body).encode()
        headers = {"User-Agent": "CodeAgent-Guard/1.0"}
        headers.update(args.get("headers") or {})
        request = urllib.request.Request(args["url"], data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                content = response.read(200_000).decode("utf-8", errors="replace")
                return {
                    "status": response.status,
                    "headers": dict(response.headers.items()),
                    "body": content,
                }
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "body": exc.read(50_000).decode(errors="replace")}

    def send_email(self, args: dict) -> dict:
        message = email.message.EmailMessage()
        message["From"] = os.getenv("SMTP_FROM", "agent@codeguard.local")
        message["To"] = args["to"]
        message["Subject"] = args.get("subject", "CodeAgent Guard notification")
        message.set_content(str(args.get("body", "")))
        host = os.getenv("SMTP_HOST")
        if host:
            port = int(os.getenv("SMTP_PORT", "587"))
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
                    smtp.starttls()
                if os.getenv("SMTP_USER"):
                    smtp.login(os.environ["SMTP_USER"], os.getenv("SMTP_PASSWORD", ""))
                smtp.send_message(message)
            return {"delivered": True, "to": args["to"], "transport": "smtp"}
        filename = self.outbox / f"{int(time.time())}-{uuid.uuid4().hex[:8]}.eml"
        filename.write_bytes(message.as_bytes())
        return {"delivered": False, "queued": True, "to": args["to"], "path": str(filename)}

    def list_directory(self, args: dict) -> dict:
        root, _ = self._resolve_authorized_path(
            args["path"],
            tool="list_directory",
        )
        if not root.exists() or not root.is_dir():
            raise NotADirectoryError(f"目录不存在: {root}")
        max_depth = int(args.get("max_depth", 2))
        include_hidden = bool(args.get("include_hidden", False))
        entries = []
        for current, directories, files in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts)
            if depth >= max_depth:
                directories[:] = []
            if not include_hidden:
                directories[:] = [name for name in directories if not name.startswith(".")]
                files = [name for name in files if not name.startswith(".")]
            for name in sorted(directories):
                path = current_path / name
                entries.append({"path": self._display_path(path), "type": "directory"})
            for name in sorted(files):
                path = current_path / name
                entries.append({
                    "path": self._display_path(path),
                    "type": "file",
                    "bytes": path.stat().st_size,
                })
            if len(entries) >= 500:
                break
        return {
            "root": str(root),
            "entries": entries[:500],
            "truncated": len(entries) >= 500,
            "external": not self._is_within(root, self.workspace),
        }

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _authorized_root(self, path: Path, roots: tuple[Path, ...]) -> Path | None:
        for root in roots:
            if self._is_within(path, root):
                return root
        return None

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.workspace))
        except ValueError:
            return str(path)

    def open_directory(self, args: dict) -> dict:
        path = Path(args["path"]).resolve(strict=False)
        authorized_roots = (
            self.workspace,
            *self.trusted_workspace_roots,
            *self.open_directory_roots,
        )
        if not any(self._is_within(path, root) for root in authorized_roots):
            raise PermissionError(f"目录未在 open_directory 授权范围内: {path}")
        if not path.exists() or not path.is_dir():
            raise NotADirectoryError(f"目录不存在: {path}")
        explorer = shutil.which("explorer.exe")
        if not explorer:
            fallback = Path("/mnt/c/Windows/explorer.exe")
            explorer = str(fallback) if fallback.exists() else None
        if not explorer:
            raise RuntimeError("当前环境未找到 Windows explorer.exe")
        converted = subprocess.run(
            ["wslpath", "-w", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        windows_path = converted.stdout.strip()
        subprocess.Popen(
            [explorer, windows_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {
            "opened": True,
            "path": str(path),
            "windows_path": windows_path,
            "application": "explorer.exe",
        }

    def search_files(self, args: dict) -> dict:
        root, _ = self._resolve_authorized_path(
            args["path"],
            tool="search_files",
        )
        if not root.exists() or not root.is_dir():
            raise NotADirectoryError(f"搜索目录不存在: {root}")
        query = str(args["query"])
        use_regex = bool(args.get("regex", False))
        pattern = re.compile(query) if use_regex else None
        glob = str(args.get("glob", "*"))
        max_results = int(args.get("max_results", 50))
        matches = []
        scanned = 0
        for path in root.rglob(glob):
            if not path.is_file() or any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            if path.stat().st_size > 1_000_000:
                continue
            scanned += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), 1):
                matched = bool(pattern.search(line)) if pattern else query in line
                if matched:
                    matches.append({
                        "path": self._display_path(path),
                        "line": line_number,
                        "text": line[:500],
                    })
                    if len(matches) >= max_results:
                        return {"matches": matches, "scanned_files": scanned, "truncated": True}
        return {"matches": matches, "scanned_files": scanned, "truncated": False}

    def make_directory(self, args: dict) -> dict:
        path, root = self._resolve_authorized_path(
            args["path"],
            tool="make_directory",
        )
        if root in self.external_write_roots and path == root:
            raise PermissionError("不能直接修改外部授权根目录本身")
        path.mkdir(parents=True, exist_ok=True)
        return {"path": str(path), "created": True}

    def delete_path(self, args: dict) -> dict:
        path, root = self._resolve_authorized_path(
            args["path"],
            tool="delete_path",
        )
        if (
            root in (*self.trusted_workspace_roots, *self.external_write_roots)
            and path == root
        ):
            raise PermissionError("不能删除外部授权根目录本身")
        if not path.exists():
            raise FileNotFoundError(f"目标不存在: {path}")
        if path.is_dir():
            path.rmdir()
            kind = "empty_directory"
        else:
            path.unlink()
            kind = "file"
        return {"path": str(path), "deleted": True, "type": kind}

    def move_path(self, args: dict) -> dict:
        source, source_root = self._resolve_authorized_path(
            args["source"],
            tool="move_path",
        )
        destination, destination_root = self._resolve_authorized_path(
            args["destination"],
            tool="move_path",
        )
        if source_root != destination_root:
            raise PermissionError("不允许在工作区和外部授权目录之间移动")
        if source_root in (
            *self.trusted_workspace_roots,
            *self.external_write_roots,
        ):
            if source == source_root or destination == destination_root:
                raise PermissionError("不能直接移动外部授权根目录本身")
        if not source.exists():
            raise FileNotFoundError(f"源路径不存在: {source}")
        if destination.exists():
            raise FileExistsError(f"目标已存在: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        return {"source": str(source), "destination": str(destination), "moved": True}
