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

import selectors
import threading
import weakref
import logging

# TODO: Make sure ALL selectors are freed
# TODO: Use a single global selector for ALL code

_thread_local = threading.local()
_all_selectors = weakref.WeakSet()

class SmartSelector(selectors.DefaultSelector):
    """
    A smart selector used with get_current_thread_selector()
    """
    def register_or_modify(self, fileobj, events, data=None):
        """Register or modify a selector."""
        try:
            return self.register(fileobj, events, data)
        except KeyError:
            return self.modify(fileobj, events, data)
        
    def wait_for(self, fileobj, timeout=0.1):
        """
        Block the current thread until the selector has an event for a certain
        item.

        Args:
            fileobj: The item to wait for.
            timeout: How long each wait should be. Defaults to 0.1.
        """
        while True:
            event = self.select(timeout=timeout)
            for key, mask in event:
                if key.fileobj == fileobj:
                    return

def _close_selector(sel):
    """
    Close a selector.

    Args:
        sel: The selector to close.
    """
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

def create_new_thread_selector() -> SmartSelector:
    """
    Create a new selector that is bound to a specific thread.

    Returns:
        A selector bound to a specific thread.
    """
    pass

def close_all_selectors():
    """Close all open selectors. """

    items = list(_all_selectors)

    if (n:=len(items)) > 0:
        logging.warning("%i selectors were not closed automatically", n)
        
    for sel in items:
        try:
            sel.close()
        except:
            pass

    _all_selectors.clear()