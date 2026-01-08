# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

from unittest.mock import patch

import pytest

from coreason_veritas.auditor import IERLogger


@pytest.mark.asyncio
async def test_log_event_success() -> None:
    auditor = IERLogger()

    with patch("coreason_veritas.auditor.logger") as mock_logger:
        details = {"user_id": "123", "action": "login"}
        await auditor.log_event("EXECUTION_START", details)

        # Verify logger.bind was called with correct arguments
        mock_logger.bind.assert_called_once_with(event_type="EXECUTION_START", **details)

        # Verify info was called on the bound logger
        mock_logger.bind.return_value.info.assert_called_once_with("Audit Event: EXECUTION_START")


@pytest.mark.asyncio
async def test_log_event_empty_details() -> None:
    auditor = IERLogger()

    with patch("coreason_veritas.auditor.logger") as mock_logger:
        await auditor.log_event("SIMPLE_EVENT", {})

        mock_logger.bind.assert_called_once_with(event_type="SIMPLE_EVENT")
        mock_logger.bind.return_value.info.assert_called_once_with("Audit Event: SIMPLE_EVENT")
