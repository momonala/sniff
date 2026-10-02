"""Host allowlist for filtering a capture down to the API you care about."""

from pathlib import Path

DEFAULT_HOSTS_FILE = Path(__file__).parents[2] / "hosts.txt"


def load_hosts(path: Path = DEFAULT_HOSTS_FILE) -> set[str]:
    """One host per line; blank lines and '#' comments ignored. Missing file -> empty set."""
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def matches(host: str, allowed: set[str]) -> bool:
    """Exact host match, or suffix match for entries written as '.example.com'."""
    for entry in allowed:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False
