"""Unit test suite for vuln-evaluator micro-agent."""

import json
import socket
import tempfile
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from vuln_evaluator.epss_client import EpssClient
from vuln_evaluator.evaluator import VulnerabilityEvaluator
from vuln_evaluator.memory_checker import MemoryChecker
from vuln_evaluator.schemas import (
    EpssData,
    MemoryCheckResult,
    VulnerabilityFinding,
)
from vuln_evaluator.socket_server import UdsEvaluationServer


def test_schema_cve_normalization():
    """Verify lowercase CVE IDs are coerced to uppercase."""
    finding = VulnerabilityFinding(
        cve_id="cve-2024-38077",
        package_name="libtest",
        installed_version="1.2.3",
        cvss_base=9.8,
    )
    assert finding.cve_id == "CVE-2024-38077"


def test_schema_invalid_cve():
    """Verify invalid CVE formats raise a ValidationError."""
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            cve_id="INVALID-CVE",
            package_name="libtest",
            installed_version="1.2.3",
            cvss_base=9.8,
        )


def test_epss_client_mocked_success(mocker):
    """Verify EPSS client parses successful FIRST.org response."""
    mock_resp = mocker.Mock()
    mock_resp.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2024-38077",
                "epss": "0.8521",
                "percentile": "0.985",
                "date": "2026-11-14",
            }
        ],
    }
    mock_resp.raise_for_status = mocker.Mock()
    mocker.patch("requests.get", return_value=mock_resp)

    client = EpssClient()
    data = client.get_epss("CVE-2024-38077")

    assert data.cve_id == "CVE-2024-38077"
    assert data.epss_score == 0.8521
    assert data.percentile == 0.985


def test_epss_client_fallback_on_network_error(mocker):
    """Verify EPSS client falls back cleanly to 0.0 on error."""
    import requests

    mocker.patch(
        "requests.get", side_effect=requests.RequestException("Connection refused")
    )

    client = EpssClient()
    data = client.get_epss("CVE-2024-99999")

    assert data.cve_id == "CVE-2024-99999"
    assert data.epss_score == 0.0
    assert data.percentile == 0.0


def test_memory_checker_finds_mapped_file():
    """Verify MemoryChecker parses /proc/<pid>/maps correctly."""
    with tempfile.TemporaryDirectory() as temp_dir:
        fake_proc = Path(temp_dir)
        pid_dir = fake_proc / "1234"
        pid_dir.mkdir()
        maps_file = pid_dir / "maps"

        # Mock /proc maps file content
        maps_file.write_text(
            "7f3a8b200000-7f3a8b250000 r-xp 00000000 08:01 12345 /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6\n"
            "7f3a8b250000-7f3a8b260000 r--p 00050000 08:01 12345 /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6\n"
        )

        checker = MemoryChecker(proc_root=temp_dir)
        result = checker.check_package_in_memory("libsqlite3")

        assert result.in_memory is True
        assert 1234 in result.matching_pids
        assert any("libsqlite3" in path for path in result.mapped_paths)


def test_evaluator_deterministic_gates():
    """Verify deterministic scoring rules."""
    evaluator = VulnerabilityEvaluator(ollama_url="http://invalid-host:11434")

    # Critical Case: High EPSS + In RAM
    finding_crit = VulnerabilityFinding(
        cve_id="CVE-2024-1111",
        package_name="libfoo",
        installed_version="1.0",
        cvss_base=9.8,
    )
    epss_crit = EpssData(cve_id="CVE-2024-1111", epss_score=0.25, percentile=0.95)
    mem_crit = MemoryCheckResult(
        in_memory=True, matching_pids=[101], mapped_paths=["/usr/lib/libfoo.so"]
    )

    res_crit = evaluator.evaluate(finding_crit, epss_crit, mem_crit)
    assert res_crit.threat_level == "CRITICAL"

    # Low Case: Low EPSS + Not In RAM
    finding_low = VulnerabilityFinding(
        cve_id="CVE-2024-2222",
        package_name="libbar",
        installed_version="2.0",
        cvss_base=8.5,
    )
    epss_low = EpssData(cve_id="CVE-2024-2222", epss_score=0.002, percentile=0.20)
    mem_low = MemoryCheckResult(in_memory=False, matching_pids=[], mapped_paths=[])

    res_low = evaluator.evaluate(finding_low, epss_low, mem_low)
    assert res_low.threat_level == "LOW"


def test_uds_socket_roundtrip(mocker):
    """Verify full IPC exchange across Unix Domain Socket."""
    with tempfile.TemporaryDirectory() as temp_dir:
        sock_path = str(Path(temp_dir) / "test_eval.sock")

        # Mock EPSS and MemoryChecker to keep test isolated
        mock_epss = mocker.Mock(spec=EpssClient)
        mock_epss.get_epss.return_value = EpssData(
            cve_id="CVE-2024-38077", epss_score=0.85, percentile=0.98
        )

        mock_mem = mocker.Mock(spec=MemoryChecker)
        mock_mem.check_package_in_memory.return_value = MemoryCheckResult(
            in_memory=True, matching_pids=[999], mapped_paths=["/opt/app/vuln.so"]
        )

        server = UdsEvaluationServer(
            socket_path=sock_path,
            epss_client=mock_epss,
            memory_checker=mock_mem,
        )

        # Run server in background thread
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        # Wait for socket to bind
        import time

        time.sleep(0.1)

        # Client sends payload
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.connect(sock_path)

        payload = [
            {
                "cve_id": "CVE-2024-38077",
                "package_name": "vuln-pkg",
                "installed_version": "1.0.0",
                "cvss_base": 9.8,
            }
        ]
        client_sock.sendall(json.dumps(payload).encode("utf-8"))
        client_sock.shutdown(socket.SHUT_WR)

        response_raw = client_sock.recv(8192).decode("utf-8")
        client_sock.close()
        server.stop()

        results = json.loads(response_raw)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-38077"
        assert results[0]["threat_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_memory_checker_uses_root_snapshot_for_unreadable_processes(tmp_path):
    """A library mapped only by a root-owned PID must be found via the memscan snapshot."""
    import json
    import time

    snap = tmp_path / "memmap.json"
    snap.write_text(
        json.dumps(
            {
                "epoch": time.time(),
                "files": {"/usr/lib/aarch64-linux-gnu/libz.so.1.2.13": [4242]},
            }
        )
    )
    empty_proc = tmp_path / "proc"
    empty_proc.mkdir()
    dpkg_info = tmp_path / "info"
    dpkg_info.mkdir()
    (dpkg_info / "zlib1g:arm64.list").write_text(
        "/usr/lib/aarch64-linux-gnu/libz.so.1.2.13\n"
    )

    checker = MemoryChecker(
        proc_root=str(empty_proc), dpkg_info_dir=str(dpkg_info), memmap_path=str(snap)
    )
    res = checker.check_package_in_memory("zlib1g")
    assert res.in_memory is True
    assert res.matching_pids == [4242]
    assert res.memory_visibility == "full"


def test_memory_checker_partial_visibility_without_snapshot(tmp_path):
    """No snapshot means a negative result is only PARTIAL visibility."""
    empty_proc = tmp_path / "proc"
    empty_proc.mkdir()
    checker = MemoryChecker(
        proc_root=str(empty_proc),
        dpkg_info_dir=str(tmp_path),
        memmap_path=str(tmp_path / "missing.json"),
    )
    res = checker.check_package_in_memory("zlib1g")
    assert res.in_memory is False
    assert res.memory_visibility == "partial"


def test_memory_checker_stale_snapshot_is_ignored(tmp_path):
    """A snapshot older than the max age must not grant full visibility."""
    import json
    import time

    snap = tmp_path / "memmap.json"
    snap.write_text(json.dumps({"epoch": time.time() - 99999, "files": {}}))
    empty_proc = tmp_path / "proc"
    empty_proc.mkdir()
    checker = MemoryChecker(
        proc_root=str(empty_proc), dpkg_info_dir=str(tmp_path), memmap_path=str(snap)
    )
    assert checker.check_package_in_memory("zlib1g").memory_visibility == "partial"


def test_evaluator_passes_strict_json_schema_and_ordinal_percentile(mocker):
    """Verify Ollama request uses strict JSON schema and unambiguous EPSS vs percentile formatting."""
    captured_payloads = []

    def fake_post(url, json=None, timeout=60):
        captured_payloads.append(json)
        resp = mocker.Mock()
        resp.raise_for_status = mocker.Mock()
        resp.json.return_value = {
            "response": '{"threat_level": "LOW", "rationale": "Not loaded in RAM with 0.68% 30-day exploit probability."}'
        }
        return resp

    mocker.patch("requests.post", side_effect=fake_post)

    evaluator = VulnerabilityEvaluator(ollama_url="http://127.0.0.1:11434")
    finding = VulnerabilityFinding(
        cve_id="CVE-2026-76844",
        package_name="zlib1g",
        installed_version="1:1.2.13",
        cvss_base=7.5,
    )
    epss = EpssData(cve_id="CVE-2026-76844", epss_score=0.00682, percentile=0.5307)
    mem = MemoryCheckResult(
        in_memory=False, matching_pids=[], mapped_paths=[], memory_visibility="full"
    )

    res = evaluator.evaluate(finding, epss, mem)
    assert res.threat_level == "LOW"
    assert "0.68%" in res.verdict_rationale
    assert len(captured_payloads) == 1
    sent = captured_payloads[0]
    assert isinstance(sent["format"], dict)
    assert sent["format"]["required"] == ["threat_level", "rationale"]
    assert "0.68%" in sent["prompt"]
    assert "53th percentile" in sent["prompt"]
