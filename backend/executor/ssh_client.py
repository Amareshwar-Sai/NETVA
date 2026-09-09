"""SSH client wrapping Paramiko with context manager support."""
from __future__ import annotations

import logging

import paramiko

logger = logging.getLogger(__name__)


class SSHClient:
    """Paramiko SSH client with run/run_sudo/put_file helpers."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int = 10,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def connect(self) -> None:
        """Establish SSH connection."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        logger.info(f"SSH connected to {self.host}:{self.port} as {self.username}")

    def run(self, command: str) -> str:
        """Execute command and return stdout. Raises on non-zero exit."""
        if self._client is None:
            raise RuntimeError("Not connected")

        logger.info(f"SSH [{self.host}] $ {command[:100]}")
        stdin, stdout, stderr = self._client.exec_command(command, timeout=30)

        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        combined = out
        if err:
            combined += "\n" + err

        if exit_code != 0:
            logger.warning(f"SSH [{self.host}] exit={exit_code}: {err[:200]}")
            # Don't raise for common non-fatal exit codes
            if exit_code > 1:
                raise RuntimeError(f"Command failed (exit {exit_code}): {err[:500]}")

        return combined.strip()

    def run_sudo(self, command: str) -> str:
        """Execute command with sudo prefix."""
        # If already root, no sudo needed
        if self.username == "root":
            return self.run(command)
        return self.run(f"echo '{self.password}' | sudo -S bash -c '{command}'")

    def put_file(self, content: str, remote_path: str) -> None:
        """Write string content to a remote file."""
        if self._client is None:
            raise RuntimeError("Not connected")

        sftp = self._client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            logger.info(f"SSH [{self.host}] wrote {remote_path}")
        finally:
            sftp.close()

    def close(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None
            logger.info(f"SSH disconnected from {self.host}:{self.port}")
