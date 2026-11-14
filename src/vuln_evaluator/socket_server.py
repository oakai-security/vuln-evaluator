"""Unix Domain Socket server accepting vulnerability findings and returning enriched assessments."""

import json
import logging
import os
import socket
import struct
from pathlib import Path

from pydantic import ValidationError

from .epss_client import EpssClient
from .evaluator import VulnerabilityEvaluator
from .memory_checker import MemoryChecker
from .schemas import EvaluationResult, VulnerabilityFinding

logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = os.environ.get("UDS_SOCKET_PATH", "/run/oakai/eval.sock")


class UdsEvaluationServer:
    """Unix Domain Socket server providing IPC vulnerability evaluation services."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        epss_client: EpssClient | None = None,
        memory_checker: MemoryChecker | None = None,
        evaluator: VulnerabilityEvaluator | None = None,
    ):
        self.socket_path = socket_path
        self.epss_client = epss_client or EpssClient()
        self.memory_checker = memory_checker or MemoryChecker()
        self.evaluator = evaluator or VulnerabilityEvaluator()
        self._running = False
        self._server_socket: socket.socket | None = None

    def start(self, max_connections: int = 5):
        """Bind socket, configure permissions, and listen for incoming connections."""
        sock_file = Path(self.socket_path)
        sock_file.parent.mkdir(parents=True, exist_ok=True)

        # Unlink stale socket if it exists
        if sock_file.exists():
            try:
                sock_file.unlink()
                logger.info("Unlinked stale socket file: %s", self.socket_path)
            except OSError as err:
                logger.warning("Failed to remove stale socket: %s", err)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        # Configure socket permissions to allow group access (0660)
        try:
            os.chmod(self.socket_path, 0o660)
        except OSError as err:
            logger.warning("Could not set socket permissions to 0660: %s", err)

        self._server_socket.listen(max_connections)
        self._running = True
        logger.info("vuln-evaluator UDS server listening on %s", self.socket_path)

        while self._running:
            try:
                conn, _ = self._server_socket.accept()
                self._handle_client(conn)
            except (OSError, KeyboardInterrupt) as err:
                if self._running:
                    logger.error("Socket accept error: %s", err)
                break

    def stop(self):
        """Stop server and clean up socket file."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        logger.info("vuln-evaluator UDS server stopped")

    def _handle_client(self, conn: socket.socket):
        """Read request payload, process evaluations, and write JSON response."""
        with conn:
            peer_info = self._get_peer_credentials(conn)
            logger.info("Accepted connection from peer: %s", peer_info)

            buffer = []
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                buffer.append(data.decode("utf-8", errors="ignore"))

            raw_body = "".join(buffer).strip()
            if not raw_body:
                logger.warning("Empty payload received from peer")
                return

            try:
                parsed = json.loads(raw_body)
                findings: list[VulnerabilityFinding] = []

                if isinstance(parsed, list):
                    findings = [
                        VulnerabilityFinding.model_validate(item) for item in parsed
                    ]
                elif isinstance(parsed, dict):
                    findings = [VulnerabilityFinding.model_validate(parsed)]

                results: list[EvaluationResult] = []
                for finding in findings:
                    epss = self.epss_client.get_epss(finding.cve_id)
                    memory = self.memory_checker.check_package_in_memory(
                        finding.package_name
                    )
                    eval_result = self.evaluator.evaluate(finding, epss, memory)
                    results.append(eval_result)

                response_payload = [res.model_dump() for res in results]
                conn.sendall(json.dumps(response_payload, indent=2).encode("utf-8"))
                logger.info("Evaluated %d vulnerabilities successfully", len(results))

            except (
                json.JSONDecodeError,
                ValidationError,
                KeyError,
                OSError,
                TypeError,
                ValueError,
            ) as err:
                logger.error("Error processing request: %s", err)
                err_response = {"error": str(err)}
                conn.sendall(json.dumps(err_response).encode("utf-8"))

    def _get_peer_credentials(self, conn: socket.socket) -> str:
        """Inspect SO_PEERCRED on Linux to log the caller PID, UID, and GID."""
        try:
            # Linux SO_PEERCRED: struct ucred { pid_t pid; uid_t uid; gid_t gid; };
            # struct format: "3i"
            creds = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", creds)
            return f"PID={pid}, UID={uid}, GID={gid}"
        except (AttributeError, OSError):
            return "unknown (SO_PEERCRED unavailable)"
