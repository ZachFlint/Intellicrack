# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: a change to a locked JSON document waits for the lock for as long as another process holds it.

On Windows the cross-process lock was taken with the C runtime's ``LK_LOCK``,
which looks for the lock once a second and after ten looks gives up with
``EDEADLOCK``. Several processes writing one approvals file back to back could
keep a queued writer looking and missing for those ten seconds, and its change
was then refused with "Resource deadlock avoided" though nothing was
deadlocked; on a loaded CI runner that failed the concurrent-writers gate.

The gate below makes the wait exceed that window on purpose: a real second
process holds the lock for longer than ten seconds while this one changes the
same document.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Final

from intellicrack.core.locked_json import LockedJsonFile
from tests._helpers.child_python import run_child_json


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.core.json_payload import JsonObject


_C_RUNTIME_GIVES_UP_AFTER_S: Final[float] = 10.0
_HOLD_S: Final[float] = _C_RUNTIME_GIVES_UP_AFTER_S + 3.0
_CHILD_TIMEOUT_S: Final[float] = 120.0
_HOLDER_START_TIMEOUT_S: Final[float] = 60.0
_POLL_S: Final[float] = 0.05


def test_a_change_waits_out_a_lock_held_longer_than_the_c_runtime_would(tmp_path: Path) -> None:
    """A change made while another process holds the lock for thirteen seconds is applied once the lock is free.

    Falsifiable: taken with the C runtime's blocking lock, the lock is given
    up after ten seconds and the change raises "Resource deadlock avoided".

    Args:
        tmp_path: Per-test directory holding the document.
    """
    document = tmp_path / "document.json"
    holding = tmp_path / "holding.marker"
    code = f"""
        import json
        import time
        from pathlib import Path

        from intellicrack.core.locked_json import LockedJsonFile

        def _hold(data):
            Path({str(holding)!r}).write_text("held", encoding="utf-8")
            time.sleep({_HOLD_S!r})
            data["holder"] = True
            return True

        LockedJsonFile(Path({str(document)!r})).update(_hold)
        print(json.dumps({{"released": True}}))
    """
    outcomes: list[dict[str, object]] = []
    failures: list[AssertionError] = []

    def _run_holder() -> None:
        """Run the process that holds the lock."""
        try:
            outcomes.append(run_child_json(code, timeout_s=_CHILD_TIMEOUT_S))
        except AssertionError as exc:
            failures.append(exc)

    holder = threading.Thread(target=_run_holder)
    holder.start()
    try:
        deadline = time.monotonic() + _HOLDER_START_TIMEOUT_S
        while not holding.exists() and time.monotonic() < deadline:
            time.sleep(_POLL_S)
        assert holding.exists(), f"the holding process never took the lock: {failures}"

        def _add(data: JsonObject) -> bool:
            """Add this process's record to the document.

            Args:
                data: The decoded document.

            Returns:
                bool: Always ``True``.
            """
            data["waiter"] = True
            return True

        started = time.monotonic()
        changed = LockedJsonFile(document).update(_add)
        waited = time.monotonic() - started
    finally:
        holder.join(timeout=_CHILD_TIMEOUT_S)

    assert failures == []
    assert outcomes == [{"released": True}]
    assert waited > _C_RUNTIME_GIVES_UP_AFTER_S, f"the change waited only {waited:.1f}s, so the long hold was never exercised"
    assert changed == {"holder": True, "waiter": True}
    assert LockedJsonFile(document).read() == {"holder": True, "waiter": True}
