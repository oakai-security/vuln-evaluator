"""Command line interface for vuln-evaluator."""

import argparse
import json
import logging

from .epss_client import EpssClient
from .evaluator import VulnerabilityEvaluator
from .memory_checker import MemoryChecker
from .schemas import VulnerabilityFinding
from .socket_server import DEFAULT_SOCKET_PATH, UdsEvaluationServer


def main():
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Autonomous Vulnerability Evaluator Micro-Agent"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Server subcommand
    serve_parser = subparsers.add_parser(
        "serve", help="Start Unix Domain Socket server daemon"
    )
    serve_parser.add_argument(
        "--socket", default=DEFAULT_SOCKET_PATH, help="Path to UDS socket file"
    )

    # Single evaluation subcommand
    eval_parser = subparsers.add_parser(
        "evaluate", help="Evaluate a single vulnerability finding"
    )
    eval_parser.add_argument(
        "--cve", required=True, help="CVE identifier (e.g. CVE-2024-38077)"
    )
    eval_parser.add_argument("--package", required=True, help="Package name")
    eval_parser.add_argument("--version", default="1.0.0", help="Installed version")
    eval_parser.add_argument("--cvss", type=float, default=5.0, help="Base CVSS score")

    # File evaluation subcommand
    file_parser = subparsers.add_parser(
        "evaluate-file", help="Evaluate findings from a JSON file"
    )
    file_parser.add_argument(
        "file_path", help="Path to JSON file containing findings array"
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if args.command == "serve":
        server = UdsEvaluationServer(socket_path=args.socket)
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()

    elif args.command == "evaluate":
        finding = VulnerabilityFinding(
            cve_id=args.cve,
            package_name=args.package,
            installed_version=args.version,
            cvss_base=args.cvss,
        )
        epss = EpssClient().get_epss(finding.cve_id)
        memory = MemoryChecker().check_package_in_memory(finding.package_name)
        result = VulnerabilityEvaluator().evaluate(finding, epss, memory)
        print(json.dumps(result.model_dump(), indent=2))

    elif args.command == "evaluate-file":
        with open(args.file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        findings = [
            VulnerabilityFinding.model_validate(item)
            for item in (raw if isinstance(raw, list) else [raw])
        ]
        epss_client = EpssClient()
        memory_checker = MemoryChecker()
        evaluator = VulnerabilityEvaluator()

        results = []
        for finding in findings:
            epss = epss_client.get_epss(finding.cve_id)
            memory = memory_checker.check_package_in_memory(finding.package_name)
            res = evaluator.evaluate(finding, epss, memory)
            results.append(res.model_dump())

        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
