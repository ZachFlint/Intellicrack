# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
import asyncio
from collections.abc import Coroutine

def run_bridge_coroutine[T](coro: Coroutine[object, object, T]) -> T | None: ...
def _log_task_exception(task: asyncio.Task[object]) -> None: ...
