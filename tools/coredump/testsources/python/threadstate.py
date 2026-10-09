# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Exercise thread-state lookup and transitions between Python and native frames."""

import os
import threading
import time


def leaf(value):
    for number in range(250_000):
        value += number * number
    return value


def recursive(depth, value):
    if depth:
        return recursive(depth - 1, value)
    return leaf(value)


def sort_key(value):
    return recursive(8, value)


def worker():
    started = time.monotonic()
    for batch in range(1, 1001):
        # sorted() calls back into Python, splitting the stack into two
        # interpreter invocations with native frames between them.
        sorted(range(3), key=sort_key)
        if batch % 25 == 0:
            rate = batch / (time.monotonic() - started)
            print(f"tid={threading.get_native_id()} batch={batch}/1000 "
                  f"rate={rate:.1f}/s eta={(1000 - batch) / rate:.0f}s", flush=True)


print(f"pid={os.getpid()}", flush=True)
thread = threading.Thread(target=worker)
thread.start()
worker()
thread.join()
