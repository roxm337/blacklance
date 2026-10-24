"""Bundled configuration and scanner rules for installed distributions."""

from importlib.resources import files
from pathlib import Path


def resource_path(relative: str) -> Path:
    """Use checkout data during development and bundled data after installation."""
    checkout = Path(__file__).resolve().parent.parent / relative
    if checkout.exists():
        return checkout
    return Path(str(files(__package__).joinpath(relative)))
