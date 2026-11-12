#!/usr/bin/env python3
"""Print the fleet hosts whose Falco SIB should expect to hear from, one per line.

Runs inside the Ansible container (make refresh-alerts). Reads the inventory
with ansible-inventory, so it never contacts the hosts: an offline host stays
expected until it is removed from the inventory. Names are inventory names,
the same value the collectors put in the `host` label.

Exclude a host that runs no Falco (an LXC container, a collector-only box)
with the host variable `sib_expected: false`.
"""
import json
import re
import subprocess
import sys

INVENTORY = sys.argv[1] if len(sys.argv) > 1 else "inventory/hosts.yml"
VALID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

data = json.loads(subprocess.run(
    ["ansible-inventory", "-i", INVENTORY, "--list"],
    check=True, capture_output=True, text=True).stdout)


def hosts_in(group, seen=None):
    seen = seen if seen is not None else set()
    if group in seen:
        return set()
    seen.add(group)
    entry = data.get(group, {})
    found = set(entry.get("hosts", []))
    for child in entry.get("children", []):
        found |= hosts_in(child, seen)
    return found


hostvars = data.get("_meta", {}).get("hostvars", {})
for host in sorted(hosts_in("fleet")):
    expected = hostvars.get(host, {}).get("sib_expected", True)
    if str(expected).lower() in ("false", "no", "0"):
        continue
    if not VALID.match(host):
        print(f"skipping host with unsupported name: {host!r}", file=sys.stderr)
        continue
    print(host)
