"""AlphaMap strategy — backend selection rules."""

from .selector import select_backends, best_backend, register_rule

__all__ = ["select_backends", "best_backend", "register_rule"]
