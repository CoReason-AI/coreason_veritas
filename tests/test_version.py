# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import tomllib
from pathlib import Path
import coreason_veritas

def test_version_sync() -> None:
    """
    Test that the version in pyproject.toml matches the version in the package.
    """
    pyproject_path = Path("pyproject.toml")
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    toml_version = data["tool"]["poetry"]["version"]
    assert coreason_veritas.__version__ == toml_version
