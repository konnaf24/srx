"""Live tests are opt-in independently of whether a probe config exists."""
from types import SimpleNamespace

import conftest


class FakeItem:
    def __init__(self, live):
        self.live = live
        self.added = []

    def get_closest_marker(self, name):
        assert name == "requires_srx"
        return object() if self.live else None

    def add_marker(self, marker):
        self.added.append(marker)


def test_live_tests_are_skipped_without_explicit_opt_in():
    live, offline = FakeItem(True), FakeItem(False)
    conftest.pytest_collection_modifyitems(
        SimpleNamespace(getoption=lambda name: False), [live, offline]
    )
    assert len(live.added) == 1
    assert live.added[0].name == "skip"
    assert "--live-srx" in live.added[0].kwargs["reason"]
    assert offline.added == []


def test_opt_in_does_not_skip_live_or_offline_tests():
    live, offline = FakeItem(True), FakeItem(False)
    conftest.pytest_collection_modifyitems(
        SimpleNamespace(getoption=lambda name: True), [live, offline]
    )
    assert live.added == offline.added == []
