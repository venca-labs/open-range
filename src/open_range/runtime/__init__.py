"""Public runtime package surface."""

__all__ = ["OpenRangeRuntime"]


def __getattr__(name: str):
    if name == "OpenRangeRuntime":
        from open_range.runtime.core import OpenRangeRuntime

        return OpenRangeRuntime
    raise AttributeError(name)
