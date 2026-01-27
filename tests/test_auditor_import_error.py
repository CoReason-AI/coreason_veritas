import importlib
import sys
from typing import Any
from unittest.mock import patch


def test_auditor_import_error() -> None:
    original_auditor = sys.modules.get("coreason_veritas.auditor")

    try:
        with patch.dict(sys.modules):
            if "coreason_veritas.auditor" in sys.modules:
                del sys.modules["coreason_veritas.auditor"]

            sys.modules["coreason_identity.models"] = None  # type: ignore

            import coreason_veritas.auditor

            # Use getattr to access UserContext safely for mypy
            uc = coreason_veritas.auditor.UserContext  # type: ignore[attr-defined]
            assert uc is Any

    finally:
        if "coreason_veritas.auditor" in sys.modules:
            del sys.modules["coreason_veritas.auditor"]

        if original_auditor:
            sys.modules["coreason_veritas.auditor"] = original_auditor
        else:
            import coreason_veritas.auditor

            importlib.reload(coreason_veritas.auditor)
