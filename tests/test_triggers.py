"""Tests for pkgids/triggers.py — TriggerPlan, TriggerResult, SUPPORTED_TRIGGER_IDS."""

from __future__ import annotations

import pytest

from pkgids.triggers import (
    SUPPORTED_TRIGGER_IDS,
    TriggerPlan,
    TriggerResult,
)


class TestSupportedTriggerIds:
    def test_is_frozenset(self):
        assert isinstance(SUPPORTED_TRIGGER_IDS, frozenset)

    def test_contains_install(self):
        assert "install" in SUPPORTED_TRIGGER_IDS

    def test_contains_import_root(self):
        assert "import_root" in SUPPORTED_TRIGGER_IDS

    def test_contains_install_with_deps(self):
        assert "install_with_deps" in SUPPORTED_TRIGGER_IDS

    def test_contains_import_submodule(self):
        assert "import_submodule" in SUPPORTED_TRIGGER_IDS

    def test_does_not_contain_dynamic_triggers(self):
        for bad in ("entry_point:*", "import_submodule:*", "baited_env", ""):
            assert bad not in SUPPORTED_TRIGGER_IDS


class TestTriggerPlan:
    def test_basic_construction(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3", "install", "pkg"),
            timeout=120,
        )
        assert plan.trigger_id == "install"
        assert plan.phase_label == "Install"
        assert plan.command == ("pip3", "install", "pkg")
        assert plan.timeout == 120

    def test_default_post_delay_is_zero(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3",),
            timeout=120,
        )
        assert plan.post_delay == 0

    def test_default_requires_is_empty_tuple(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3",),
            timeout=120,
        )
        assert plan.requires == ()

    def test_default_dependency_skip_reason_is_none(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3",),
            timeout=120,
        )
        assert plan.dependency_skip_reason is None

    def test_explicit_post_delay(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3",),
            timeout=120,
            post_delay=5,
        )
        assert plan.post_delay == 5

    def test_explicit_requires(self):
        plan = TriggerPlan(
            trigger_id="import_root",
            phase_label="Import (root)",
            command=("python3", "-c", "import six"),
            timeout=30,
            requires=("install",),
            dependency_skip_reason="install_failed",
        )
        assert plan.requires == ("install",)
        assert plan.dependency_skip_reason == "install_failed"

    def test_is_frozen_immutable(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3",),
            timeout=120,
        )
        with pytest.raises((AttributeError, TypeError)):
            plan.trigger_id = "changed"  # type: ignore[misc]

    def test_is_hashable(self):
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=("pip3", "install", "pkg"),
            timeout=120,
        )
        # Hashable because frozen=True and command is a tuple.
        assert hash(plan) == hash(plan)

    def test_command_must_be_tuple(self):
        # Tuples are required for hashability; lists would break frozen dataclass hashing.
        plan = TriggerPlan(
            trigger_id="install",
            phase_label="Install",
            command=tuple(["pip3", "install"]),
            timeout=120,
        )
        assert isinstance(plan.command, tuple)


class TestTriggerResult:
    def _make(self, **kwargs) -> TriggerResult:
        defaults: dict = dict(
            trigger_id="install",
            phase_label="Install",
            status="ok",
            t_start=1000.0,
            t_end=1005.0,
            stdout="",
            stderr="",
            exit_code=0,
            timed_out=False,
            network_activity=False,
            process_activity={},
        )
        defaults.update(kwargs)
        return TriggerResult(**defaults)

    def test_basic_fields(self):
        r = self._make()
        assert r.trigger_id    == "install"
        assert r.status        == "ok"
        assert r.t_start       == 1000.0
        assert r.t_end         == 1005.0
        assert r.exit_code     == 0
        assert r.timed_out     is False
        assert r.network_activity is False

    def test_skip_reason_defaults_to_none(self):
        r = self._make()
        assert r.skip_reason is None

    def test_skip_reason_explicit(self):
        r = self._make(status="skipped", exit_code=None, skip_reason="install_failed")
        assert r.skip_reason == "install_failed"

    def test_is_mutable(self):
        r = self._make()
        r.status = "failed"
        assert r.status == "failed"

    def test_status_values(self):
        for status in ("ok", "failed", "timed_out", "crashed", "module_not_found", "skipped"):
            r = self._make(status=status)
            assert r.status == status

    def test_network_activity_bool(self):
        r_false = self._make(network_activity=False)
        r_true  = self._make(network_activity=True)
        assert r_false.network_activity is False
        assert r_true.network_activity  is True

    def test_process_activity_dict(self):
        pa = {"process_count": 3, "any_suspicious": True}
        r  = self._make(process_activity=pa)
        assert r.process_activity == pa
