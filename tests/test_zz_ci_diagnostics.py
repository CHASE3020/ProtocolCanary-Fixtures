"""Temporary diagnostic: print unittest failures as check-run annotations.

The GitHub Actions job log is not readable without an authenticated session, so
a failing step only reports "exit code 1". This module (loaded by discovery
before the tests run) adds a workflow command for every failure and error, which
GitHub turns into a check-run annotation whose message names the test.

Delete this file once the cross-platform failure is understood.
"""
from __future__ import annotations

import traceback
import unittest


def _recording(original):
    def wrapper(self, test, err):  # type: ignore[no-untyped-def]
        original(self, test, err)
        summary = "".join(traceback.format_exception_only(err[0], err[1])).strip()
        message = f"{test.id()}: {summary}"
        message = message.replace("%", "%25").replace("\r", "").replace("\n", " | ")
        print(f"::error title=failing test::{message[:900]}", flush=True)

    return wrapper


unittest.TestResult.addFailure = _recording(unittest.TestResult.addFailure)
unittest.TestResult.addError = _recording(unittest.TestResult.addError)
