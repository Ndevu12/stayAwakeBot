#!/usr/bin/env python3
"""A loader that resolves its next stage from a blockchain transaction, then runs it.

This family hides its C2 on-chain: it reads an address's transactions (or one transaction by hash)
from a public explorer or RPC, takes a transaction's `input` as code, and runs it through an
interpreter. The same design appears in the JavaScript `init` carrier and in a Python `utils/session.py`
module spliced into a script a project already runs — so the signatures key on the behaviour, not on
one language, and a finding is asserted only when a fetched stage is actually run (an exec sink in JS
OR Python), so legit explorer/RPC reads that only display data stay clean.
"""
from __future__ import annotations

import re
import unittest

import yaml

from pathlib import Path
from stayawake.bots.security.matchers.content import CORROBORATORS, _corroborated, _runs_fetched_stage
from tests.support import samples

_SIGNATURES = Path(__file__).resolve().parents[3] / "src/stayawake/bots/security/data/signatures.yml"
_FREEKEY = samples.joined("free", "key")
_GET_TX = samples.joined("eth_getTransaction", "ByHash")


def _signature(sig_id):
    for entry in yaml.safe_load(_SIGNATURES.read_text())["signatures"]:
        if entry.get("id") == sig_id:
            return entry
    raise AssertionError(f"{sig_id} is not in the signature file")


def _fires(signature, pattern, source):
    match = pattern.search(source)
    if not match:
        return False
    if signature.get("corroborate"):
        return _corroborated(signature["corroborate"], source, match.start(), match.end())
    return True


class TestTheEthplorerEnumerationIsConfirmedOnlyWhenAStageRuns(unittest.TestCase):
    def setUp(self):
        self.sig = _signature("chain-c2-ethplorer-enum")
        self.pattern = re.compile(self.sig["pattern"], re.IGNORECASE)

    def test_it_asserts_malware_when_it_fires(self):
        self.assertEqual(self.sig["severity"], "critical")
        self.assertNotEqual(self.sig.get("confidence"), "heuristic")

    def test_an_enumeration_whose_stage_runs_fires(self):
        src = (f'url = "https://api.ethplorer.io/getAddressTransactions/0xabc?apiKey={_FREEKEY}"\n'
               'data = urllib.request.urlopen(url).read()\n'
               'subprocess.run(["node", staged_file])\n')
        self.assertTrue(_fires(self.sig, self.pattern, src))

    def test_a_demo_that_only_prints_stays_clean(self):
        src = (f'url = "https://api.ethplorer.io/getAddressTransactions/0xabc?apiKey={_FREEKEY}"\n'
               'for t in json.load(urllib.request.urlopen(url)):\n    print(t["hash"], t.get("value"))\n')
        self.assertFalse(_fires(self.sig, self.pattern, src))


class TestTheTransactionByHashShapeIsSuspiciousWhenAStageRuns(unittest.TestCase):
    def setUp(self):
        self.sig = _signature("chain-c2-tx-by-hash-exec")
        self.pattern = re.compile(self.sig["pattern"], re.IGNORECASE)

    def test_it_surfaces_as_suspicious_not_infected(self):
        self.assertEqual(self.sig.get("confidence"), "heuristic")

    def test_fetching_a_transaction_then_running_a_stage_fires(self):
        src = (f'body = {{"method": "{_GET_TX}", "params": [h]}}\n'
               'tx = rpc(body)\n'
               'subprocess.run(["node", bytes.fromhex(tx["input"][2:])])\n')
        self.assertTrue(_fires(self.sig, self.pattern, src))

    def test_reading_a_transaction_without_running_anything_stays_clean(self):
        src = (f'body = {{"method": "{_GET_TX}", "params": [h]}}\n'
               'tx = rpc(body)\nprint("value", int(tx["value"], 16))\n')
        self.assertFalse(_fires(self.sig, self.pattern, src))


class TestTheStageRunnerSpansJavaScriptAndPython(unittest.TestCase):
    """The corroborator is additive: it keeps the shared JavaScript exec-sink detector and adds the
    Python process-spawns this family uses. Pinned so the Python side cannot regress and the JS side
    is shown unchanged."""

    def test_python_process_spawns_count_as_running_a_stage(self):
        for sink in ('subprocess.run(["node", f])', 'subprocess.Popen(["node", f])',
                     "os.system('node ' + f)", "os.popen('node ' + f)"):
            with self.subTest(sink=sink):
                self.assertTrue(_runs_fetched_stage(sink))

    def test_the_javascript_exec_sink_still_counts(self):
        js = samples.joined("const d = atob(x); require('child_", "process').execSync(d)")
        self.assertTrue(_runs_fetched_stage(js))

    def test_ordinary_code_does_not_count(self):
        self.assertFalse(_runs_fetched_stage("value = int(tx['value'], 16)\nprint(value)\n"))


class TestTheCorroboratorNameIsRegistered(unittest.TestCase):
    def test_the_signatures_name_a_real_corroborator(self):
        for sig_id in ("chain-c2-ethplorer-enum", "chain-c2-tx-by-hash-exec"):
            with self.subTest(signature=sig_id):
                name = _signature(sig_id).get("corroborate")
                if name:
                    self.assertIn(name, CORROBORATORS)


if __name__ == "__main__":
    unittest.main()
