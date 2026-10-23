"""
pytest-xdist scheduler: hands out the slowest tests first. Loaded by tests/conftest.py, used by `pytest -n N`
(--dist load, the default of -n). Other --dist modes keep the scheduler of xdist.

The stock scheduler sends each worker a chunk of consecutive tests, so two slow tests that sit next to each other (the
same test on gdb and on libdebug) run one after the other on one worker, and when they start late the run ends with
one worker busy and the others idle. This one orders the tests by their latest recorded duration (any
tests/.results/<version>.json, any flavor), longest first, and gives a worker one test at a time: every worker has the
test it runs and the next one queued (an xdist worker only starts a test once it knows the one after it). The run then
lasts about max(total time / workers, slowest test).

A test with no recorded duration (new, or the results directory is empty) goes first: it may be slow. Durations are
rounded to 0.1s and the sort is stable, so the fast tests keep the collection order (module fixtures stay shared).
"""
import json
import os
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent.parent
RESULTS = Path(os.environ.get("GDB_PLUS_RESULTS_DIR", TESTS / ".results"))
QUEUED = 2  # tests sent to a worker ahead: the one it runs and the next


def recorded_durations():
    """Node id -> duration in seconds of its latest recorded run, across the results files and the flavors."""
    latest = {}
    for path in sorted(RESULTS.glob("*.json")):
        try:
            results = json.loads(path.read_text()).get("results")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(results, dict):
            continue
        for key, entry in results.items():
            if not isinstance(entry, dict) or entry.get("duration") is None:
                continue
            nodeid = key.split("|", 1)[-1]
            if entry.get("when", 0) >= latest.get(nodeid, (0, None))[0]:
                latest[nodeid] = (entry.get("when", 0), entry["duration"])
    return {nodeid: duration for nodeid, (_, duration) in latest.items()}


def longest_first(collection, durations):
    """Indices of `collection` (node ids), the longest expected first. Unknown tests count as infinitely long."""
    return sorted(range(len(collection)), key=lambda i: -round(durations.get(collection[i], float("inf")), 1))


try:
    from xdist.scheduler import LoadScheduling
except ImportError:
    LoadScheduling = None
else:
    class LongestFirstScheduling(LoadScheduling):
        """
        LoadScheduling with the pending tests sorted by expected duration and sent one at a time. Runs in the
        controller; the workers collect in the usual order (xdist requires the same collection on every worker).
        """
        def schedule(self):
            assert self.collection_is_completed
            if self.collection is not None:
                return super().schedule()
            if not self._check_nodes_have_same_collection():
                self.log("**Different tests collected, aborting run**")
                return
            self.collection = list(self.node2collection.values())[0]
            if not self.collection:
                return
            self.pending[:] = longest_first(self.collection, recorded_durations())
            # Round robin: the QUEUED longest tests of each worker are spread over all the workers
            for _ in range(QUEUED):
                for node in self.nodes:
                    self._send_tests(node, 1)
            if not self.pending:
                for node in self.nodes:
                    node.shutdown()

        def check_schedule(self, node, duration=0):
            """Called when `node` finished a test (or a node went down): top its queue up to QUEUED tests."""
            if node.shutting_down:
                return
            if self.pending:
                self._send_tests(node, max(0, QUEUED - len(self.node2pending[node])))
            else:
                node.shutdown()


@pytest.hookimpl(tryfirst=True, optionalhook=True)
def pytest_xdist_make_scheduler(config, log):
    if LoadScheduling is None or config.getvalue("dist") != "load":
        return None
    return LongestFirstScheduling(config, log)
