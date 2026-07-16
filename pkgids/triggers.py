"""TriggerPlan and TriggerResult dataclasses for multi-trigger sandbox execution.

Only the trigger IDs listed in SUPPORTED_TRIGGER_IDS are accepted in v1.5.
Dynamic discovery (entry_point:*, import_submodule:*, baited_env) is deferred.
"""

from __future__ import annotations

from dataclasses import dataclass


# Trigger IDs supported in v1.5.
SUPPORTED_TRIGGER_IDS: frozenset[str] = frozenset({
    "install",
    "import_root",
    "import_submodule",
    "install_with_deps",
})


@dataclass(frozen=True)
class TriggerPlan:
    """Specification for one execution trigger inside the sandbox.

    Attributes
    ----------
    trigger_id:
        Stable slug, e.g. "install", "import_root", "install_with_deps".
    phase_label:
        Human-readable label for display, e.g. "Install", "Import (root)".
    command:
        Full argv passed to exec_in_sandbox.  Must be a tuple so TriggerPlan
        is hashable (frozen dataclass with no mutable fields).
    timeout:
        Exec timeout in seconds.
    post_delay:
        Seconds to sleep in-container after the main command completes.
        Replaces the former post_install_idle / post_import_idle pseudo-phases:
        the backward-compat phases shim still surfaces these as separate entries
        in run.json["phases"] when post_delay > 0.
    requires:
        trigger_ids that must have status "ok" before this trigger runs.
        A trigger whose dependency did not complete with "ok" is recorded as
        skipped with dependency_skip_reason (or a generic message).
    dependency_skip_reason:
        Exact reason string written to phases[...]["reason"] when this trigger
        is skipped because a required dependency did not complete ok.
        Preserved for backward compat (e.g. "install_failed").
    """

    trigger_id:              str
    phase_label:             str
    command:                 tuple[str, ...]
    timeout:                 int
    post_delay:              int             = 0
    requires:                tuple[str, ...] = ()
    dependency_skip_reason:  str | None      = None


@dataclass
class TriggerResult:
    """Outcome of running one TriggerPlan in the sandbox.

    All timing is wall-clock (time.time()) so it is directly comparable
    with fakeinternet JSONL timestamps for per-trigger network correlation.

    status values: ok | timed_out | crashed | failed | module_not_found | skipped
    """

    trigger_id:       str
    phase_label:      str
    status:           str
    t_start:          float
    t_end:            float
    stdout:           str
    stderr:           str
    exit_code:        int | None
    timed_out:        bool
    network_activity: bool
    process_activity: dict         # output of telemetry.summarise_telemetry()
    skip_reason:      str | None = None
