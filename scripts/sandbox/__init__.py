# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Docker sandbox host-side driver package.

This package contains the host driver for running Intellicrack's test suite
inside a Windows process-isolated Docker container. It defines the test types,
builds pytest argument vectors, orchestrates container execution, and harvests
structured reports from timestamped artifact directories.
"""
