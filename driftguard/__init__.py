"""DriftGuard: catch AI agents that drift from their declared role, even with valid credentials."""
__version__ = "0.1.0"

from .contracts import ContractRegistry, RoleContract  # noqa: E402
from .detector import DriftGuard, Session, Verdict, tier  # noqa: E402

__all__ = ["ContractRegistry", "RoleContract", "DriftGuard", "Session", "Verdict", "tier", "__version__"]
