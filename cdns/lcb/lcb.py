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


"""
LifeCycle-Broadcast (LCB) Framework
"""

"""
This module implements a lifecycle framework for OOP in Python. A class is
generated from a factory. Certain mixins can be passed to this factory. The
class calls these mixins via class.lcb.start and class.lcb.end inside the code,
representing the life cycle of a class.

Usage:

class Mixin(BaseMixin):
    events = ["abcdef"]
    def start(self, target, *args, **kwargs):
        print("Started on", target)
    def end(self, target, *args, **kwargs):
        print("Ended on", target)
    
    def event(self, target, name, *args, **kwargs):
        if name == "abcdef":
            print("Received abcdef on", target)

class BaseFoo(LCBMethods):
    def somemethod(self):
        ...
        self.lcb.start()

    def anothermethod(self):
        ...
        self.lcb.end()

    def something(self):
        ...
        self.broadcast("abcdef")

def make_foo(name):
    return LCBMetaclass(name, (BaseFoo,), {}, mixins=[Mixin])

foo = make_foo()

>>> bar = foo()
>>> bar.somemethod()
Started on <cdns.lcb.lcb.foo object at 0x10346f190>
>>> bar.anothermethod()
Ended on <cdns.lcb.lcb.foo object at 0x10346f190>
>>> bar.something()
Received abcdef on <cdns.lcb.lcb.f object at 0x10346f190>
"""


EVENT_START = "_start"
EVENT_END = "_end"

class BaseMixin:
    """
    Base mixin class.
    """
    events = []
    def __init__(self):
        pass

    def receive(self, target, name, *args, **kwargs):
        if name == EVENT_START:
            return self.start(target, *args, **kwargs)
        elif name == EVENT_END:
            return self.end(target, *args, **kwargs)
        return self.event
        

    def start(self, target, *args, **kwargs):
        pass

    def end(self, target, *args, **kwargs):
        pass

    def event(self, target, name, *args, **kwargs):
        pass

class _MixinManager:
    def __init__(self, *mixins):
        self.mixins = {}

        for mixin in mixins:
            self.add(mixin)

    def add(self, obj):
        self.mixins[type(obj)] = obj

    def remove(self, obj):
        del self.mixins[type(obj)]

    def has(self, obj):
        return self.__contains__(obj)

    def __contains__(self, obj):
        return obj in self.mixins
    
    def __iter__(self):
        yield from self.mixins.values()


class _Methods:
    mixins: _MixinManager = None

    def __init__(self, proxied_self, mixins):
        self.proxied_self = proxied_self
        self.mixins = mixins

    def broadcast(self, name, *args, **kwargs) -> None:
        # Iterate and apply all the mixins
        for mixin in self.mixins:
            # Automatically listen to EVENT_START and EVENT_END
            if name in [EVENT_START, EVENT_END] or name in mixin.events:
                mixin.receive(self.proxied_self, name, *args, **kwargs)

    
    def start(self, *args, **kwargs) -> None:
        self.broadcast(EVENT_START, *args, **kwargs)

    
    def end(self, *args, **kwargs) -> None:
        self.broadcast(EVENT_END, *args, **kwargs)



class LCBMetaclass(type):
    """
    A metaclass to create a life cycle.
    """
    def __new__(cls, clsname: str, bases: tuple[type, ...], attrs: dict[str, object], mixins: list[BaseMixin] = None) -> "LCBMetaclass":
        """
        Create and return a new class.

        Args:
            cls: The metaclass itself.
            clsname: The name of the class being created.
            bases: Base classes of the new class.
            attrs: Attribute dictionary for the new class.

            mixins: Mixins for the new class. Defaults to None.

        Returns:
            The new class.
        """

        # No mixins
        if mixins is None:
            mixins = _MixinManager()
        else:
            mixins = _MixinManager(*mixins)

        class _GetMethods:
            def __get__(self, instance, owner):
                return _Methods(instance, mixins)
        
        attrs["lcb"] = _GetMethods()

        cls = super().__new__(cls, clsname, bases, attrs)
        return cls

class LCBMethods:
    """
    Stub class for type annotations of LCB.
    """
    lcb: _Methods = None