# compactdns
# A lightweight DNS server with easy customization
# https://github.com/ninjamar/compactdns
# Copyright (c) 2025 ninjamar

# MIT License

# Copyright (c) 2025 ninjamar

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import errno
import functools
import logging
import selectors
import threading
import time
import weakref
from typing import Any

# TODO: Make sure ALL selectors are freed
# TODO: Use a single global selector for ALL code

_thread_local = threading.local()
_all_selectors = weakref.WeakSet()


class SmartSelector(selectors.DefaultSelector):

    @functools.wraps(selectors.DefaultSelector.__init__)
    def __init__(self):
        super().__init__()

        self._closed = False

    @functools.wraps(selectors.DefaultSelector.close)
    def close(self):
        super().close()
        self._closed = True

    def safe_select(
        self, timeout: float | None = None
    ):  # return is infered automatically
        """
        Select, but do so in a safe manner.

        Args:
            timeout: Timeout to make selection.

        Returns:
            An iterable containing keys and masks.
        """
        try:
            return self.select(timeout)
        except OSError as e:
            if e.errno == errno.EBADF:
                return ()
            raise e
        except ValueError as e:
            # MacOS
            if "I/O operation on closed kqueue object" in str(e):
                return ()
            raise e

    @property
    def is_open(self):
        return not self._closed

    """
    A smart selector used with get_current_thread_selector()
    """

    def register_or_modify(self, fileobj, events, data=None):
        """Register or modify a selector."""
        try:
            return self.register(fileobj, events, data)
        except KeyError:
            return self.modify(fileobj, events, data)

    def wait_for(self, fileobj, sel_timeout=0.1, max_timeout=10):
        """
        Block the current thread until the selector has an event for a certain
        item.

        Args:
            fileobj: The item to wait for.
            timeout: How long each wait should be. Defaults to 0.1.
        """
        # TODO: Exponentional backoff
        start = time.time()
        while self.is_open:
            if max_timeout is not None and (time.time() - start) >= max_timeout:
                raise TimeoutError("Wait for operation timed out")

            event = self.safe_select(timeout=sel_timeout)
            for key, mask in event:
                if key.fileobj == fileobj:
                    return


def _close_selector(sel):
    """
    Close a selector.

    Args:
        sel: The selector to close.
    """
    logging.debug("Closing selector %s", sel)
    # TODO: Mess ts up with sigint

    try:
        sel.close()
    except:
        pass


def get_current_thread_selector() -> SmartSelector:
    """
    Get the selector for the current thread. This allows each thread to have its
    own selector. Once the thread exits, the selector gets closed automatically.

    CAVEAT: When looping over events, make sure to get the CORRECT event.
    CAVEAT: Each socket can only be registered once,

    Returns:
        The selector for the current thread.
    """
    if not hasattr(_thread_local, "sel"):
        sel = SmartSelector()

        _thread_local.sel = sel
        _all_selectors.add(sel)

        # Automatically close the selector when the thread exists
        weakref.finalize(sel, _close_selector, sel)

    return _thread_local.sel


def close_all_selectors():
    """Close all open selectors."""

    # TODO: Could iter be used?
    for sel in list(_all_selectors):
        try:
            sel.close()
        except:
            pass

    _all_selectors.clear()
