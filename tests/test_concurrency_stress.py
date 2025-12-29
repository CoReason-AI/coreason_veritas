# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import asyncio
import json
import os
import random
from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from coreason_veritas.anchor import is_anchor_active
from coreason_veritas.wrapper import governed_execution


@pytest.fixture  # type: ignore[misc]
def key_pair() -> Tuple[RSAPrivateKey, str]:
    """Generates a private/public key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_key, pem_public


def sign_payload(payload: Dict[str, Any], private_key: RSAPrivateKey) -> str:
    """Helper to sign a payload."""
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return str(signature.hex())


@pytest.mark.asyncio  # type: ignore[misc]
async def test_concurrency_stress_test(key_pair: Tuple[RSAPrivateKey, str]) -> None:
    """
    Stress test for concurrency.
    Runs a large number of governed and ungoverned tasks concurrently to ensure
    ContextVar isolation is maintained under load.
    """
    private_key, public_key_pem = key_pair

    # Configuration
    NUM_TASKS = 200

    # Prepare governed payload
    payload = {"data": "stress_test"}
    signature = sign_payload(payload, private_key)

    with patch.dict(os.environ, {"COREASON_VERITAS_PUBLIC_KEY": public_key_pem}):
        with patch("coreason_veritas.auditor.trace.get_tracer") as mock_get_tracer:
            # Mock Tracer Setup
            mock_tracer = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

            # Define Governed Task
            @governed_execution(asset_id_arg="spec", signature_arg="sig", user_id_arg="user")
            async def governed_task(spec: Dict[str, Any], sig: str, user: str, task_id: int) -> str:
                # Random sleep to force context switching
                await asyncio.sleep(random.uniform(0.001, 0.01))

                # Check Anchor State
                if not is_anchor_active():
                    return f"Governed Task {task_id}: FAILED (Anchor inactive)"

                return "OK"

            # Define Ungoverned Task
            async def ungoverned_task(task_id: int) -> str:
                # Random sleep to force context switching
                await asyncio.sleep(random.uniform(0.001, 0.01))

                # Check Anchor State
                if is_anchor_active():
                    return f"Ungoverned Task {task_id}: FAILED (Anchor active)"

                return "OK"

            # Create Tasks
            tasks = []
            for i in range(NUM_TASKS):
                if i % 2 == 0:
                    tasks.append(governed_task(spec=payload, sig=signature, user=f"user-{i}", task_id=i))
                else:
                    tasks.append(ungoverned_task(task_id=i))

            # Run concurrently
            results = await asyncio.gather(*tasks)

            # Analyze Results
            failures = [res for res in results if res != "OK"]

            assert not failures, f"Concurrency stress test failed with {len(failures)} errors: {failures[:5]}..."
