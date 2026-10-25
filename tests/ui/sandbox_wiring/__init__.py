# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for the ``wire_sandbox_backend`` injection path.

The panel-level :meth:`ToolOutputPanel.wire_sandbox_backend` must have a production caller.
This package validates the plugin / CLI / startup injection path:

* :meth:`MainWindow.wire_sandbox_backend` forwards an externally
  constructed ``SandboxBase`` (and optional ``SandboxManager``) to
  the tool panel and exposes the resulting bridge through
  :meth:`ToolOutputPanel.get_sandbox_bridge`.
* :func:`intellicrack.main._wire_preregistered_sandbox` walks the
  orchestrator's tool registry at startup and forwards any
  pre-registered sandbox instance to
  :meth:`MainWindow.wire_sandbox_backend`.
"""
