"""Tests for threatintel/update-feeds.sh, offline with fixture feeds."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

# Fixture feeds, in the formats the real ones use. Some end without a newline.
FEEDS = {
    "feodotracker": "# Feodo\r\n203.0.114.1\r\n198.51.99.7\r\n# END 2 entries",  # CRLF, like the real one
    "et_compromised": "45.1.1.1\n45.1.1.2\n203.0.114.1\n",
    "ci_army": "1.2.3.4\n",
    "spamhaus_drop": "; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n2.56.192.0/22 ; SBL459831\n",
    "blocklist_ssh": "9.9.9.1\n9.9.9.2",
    "blocklist_all": "\n".join([
        "8.8.4.4",
        # Not addresses, or not public: all dropped.
        "10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.5.5", "100.64.1.1", "169.254.169.254",
        "0.0.0.0", "224.0.0.1", "192.0.2.10", "999.1.1.1", "1.2.3", "1.2.3.4.5",
        '5.5.5.5"]', "6.6.6.6/0", "2001:db8::1", "<html>",
    ]),
}


@pytest.fixture
def ti(tmp_path):
    (tmp_path / "feeds").mkdir()
    for name, text in FEEDS.items():
        (tmp_path / "feeds" / f"{name}.txt").write_text(text)
    return tmp_path


def run(d, **env):
    r = subprocess.run(
        ["bash", str(REPO / "threatintel/update-feeds.sh")],
        env={"PATH": os.environ["PATH"], "THREATINTEL_OFFLINE": "1", "THREATINTEL_DIR": str(d), **env},
        capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def rules(d):
    doc = yaml.safe_load((d / "falco_threatintel_rules.yaml").read_text())
    lists = {e["list"]: e["items"] for e in doc if "list" in e}
    names = [e["rule"] for e in doc if "rule" in e]
    return lists, names


def test_lists_in_feed_priority_order(ti):
    run(ti)
    lists, names = rules(ti)
    # C2 feed first, then the others in FEEDS order; duplicates keep their first place.
    assert lists["threatintel_ips"] == [
        "203.0.114.1", "198.51.99.7", "45.1.1.1", "45.1.1.2", "1.2.3.4", "9.9.9.1", "9.9.9.2", "8.8.4.4"]
    assert lists["threatintel_c2_ips"] == ["203.0.114.1", "198.51.99.7"]
    assert lists["threatintel_nets"] == ["1.10.16.0/20", "2.56.192.0/22"]
    assert names == ["Connection to Known C2 Server", "Connection to Threat Intel IP (Outbound)",
                     "Connection from Threat Intel IP (Inbound)", "Connection to Crypto Mining Pool"]


def test_cap_keeps_the_highest_priority_feeds(ti):
    run(ti, MAX_THREATINTEL_IPS="3", MAX_THREATINTEL_NETS="1")
    lists, _ = rules(ti)
    assert lists["threatintel_ips"] == ["203.0.114.1", "198.51.99.7", "45.1.1.1"]
    assert lists["threatintel_nets"] == ["1.10.16.0/20"]


def test_feeds_without_final_newline_are_not_glued(ti):
    run(ti)
    combined = (ti / "feeds/combined_blocklist.txt").read_text().split()
    assert "9.9.9.2" in combined and "8.8.4.4" in combined  # blocklist_ssh ends without a newline
    assert all(c.count(".") == 3 for c in combined)


def test_an_address_no_feed_lists_any_more_drops_out(ti):
    run(ti)
    assert "1.2.3.4" in (ti / "feeds/combined_blocklist.txt").read_text().split()
    (ti / "feeds/ci_army.txt").write_text("4.3.2.1\n")
    run(ti)
    combined = (ti / "feeds/combined_blocklist.txt").read_text().split()
    assert "1.2.3.4" not in combined and "4.3.2.1" in combined


def test_empty_feeds_still_give_loadable_lists(tmp_path):
    (tmp_path / "feeds").mkdir()
    run(tmp_path)
    lists, _ = rules(tmp_path)
    assert lists == {"threatintel_ips": ["192.0.2.1"], "threatintel_nets": ["192.0.2.0/32"],
                     "threatintel_c2_ips": ["192.0.2.2"]}


def test_lookup(ti):
    run(ti)
    r = subprocess.run(["bash", str(ti / "lookup-ip.sh"), "9.9.9.2"], capture_output=True, text=True)
    assert "FOUND in blocklist_ssh" in r.stdout and "in combined blocklist" in r.stdout
    r = subprocess.run(["bash", str(ti / "lookup-ip.sh"), "9.9.9.29"], capture_output=True, text=True)
    assert "FOUND" not in r.stdout and "not found" in r.stdout


@pytest.mark.skipif(not shutil.which("docker") or os.environ.get("SIB_TEST_FALCO") != "1",
                    reason="set SIB_TEST_FALCO=1 to load the rules into Falco (needs Docker)")
def test_rules_load_in_falco(ti):
    run(ti)
    ver = os.environ.get("FALCO_VERSION", "0.45.2")
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{ti}/falco_threatintel_rules.yaml:/sib/ti.yaml:ro",
         f"falcosecurity/falco:{ver}", "falco", "-V", "/etc/falco/falco_rules.yaml", "-V", "/sib/ti.yaml"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
