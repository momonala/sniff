"""Read a mitmproxy capture and dump the matching flows to JSON, dropping SDK/analytics noise."""

import argparse
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import io
from mitmproxy.http import HTTPFlow
from rich.console import Console
from rich.table import Table

from sniff.filters import DEFAULT_HOSTS_FILE, load_hosts, matches
from sniff.proto import decode as decode_proto

DEFAULT_INPUT = Path(__file__).parents[2] / "data" / "raw" / "capture.flow"
DEFAULT_OUTPUT = Path(__file__).parents[2] / "data" / "processed" / "flows.json"


def _body(message) -> object:
    """Text for text bodies; a decoded field-number tree for protobuf (or anything that parses as it)."""
    if message is None:
        return None
    raw = message.get_content(strict=False) or b""
    if not raw:
        return ""
    try:
        return {"protobuf": decode_proto(raw)}
    except ValueError:
        return message.get_text(strict=False)


def _http_flows(input_path: Path):
    """HTTP flows only; wireguard captures also hold DNS/UDP flows."""
    with input_path.open("rb") as f:
        yield from (flow for flow in io.FlowReader(f).stream() if isinstance(flow, HTTPFlow))


def extract(input_path: Path, output_path: Path, hosts: set[str]) -> list[dict]:
    flows = []
    for flow in _http_flows(input_path):
        if hosts and not matches(flow.request.pretty_host, hosts):
            continue
        flows.append(
            {
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "request_headers": dict(flow.request.headers),
                "request_body": _body(flow.request),
                "response_status": flow.response.status_code if flow.response else None,
                "response_headers": dict(flow.response.headers) if flow.response else None,
                "response_body": _body(flow.response),
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        json.dump(flows, f, indent=2)

    return flows


def print_summary(flows: list[dict], output_path: Path) -> None:
    console = Console()
    counts = Counter((f["method"], urlparse(f["url"]).netloc, urlparse(f["url"]).path) for f in flows)

    table = Table(title=f"{len(flows)} flows -> {output_path}", header_style="bold cyan")
    table.add_column("Count", justify="right", style="dim")
    table.add_column("Method", style="magenta")
    table.add_column("Host", style="dim")
    table.add_column("Path", style="bold")

    for (method, host, path), count in sorted(counts.items(), key=lambda item: (item[0][1], item[0][2])):
        table.add_row(str(count), method, host, path)

    console.print(table)


def list_hosts(input_path: Path) -> None:
    """Print every host seen in the capture, so you know what to put in hosts.txt."""
    counts: Counter[str] = Counter()
    for flow in _http_flows(input_path):
        counts[flow.request.pretty_host] += 1
    for host, n in counts.most_common():
        print(f"{n:6d}  {host}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="host to keep (repeatable; '.example.com' matches subdomains). Overrides hosts.txt.",
    )
    parser.add_argument("--hosts-file", type=Path, default=DEFAULT_HOSTS_FILE)
    parser.add_argument("--list-hosts", action="store_true", help="just print the hosts seen in the capture and exit")
    args = parser.parse_args()

    if args.list_hosts:
        list_hosts(args.input)
        return

    hosts = set(args.host) or load_hosts(args.hosts_file)
    if not hosts:
        print("no host filter given (no --host and no hosts.txt); keeping every flow")

    flows = extract(args.input, args.output, hosts)
    print_summary(flows, args.output)
