# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_veritas

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Generator

import pytest
import requests  # type: ignore[import-untyped]
import urllib3
from requests.exceptions import ReadTimeout  # type: ignore[import-untyped]


class MockServerHandler(BaseHTTPRequestHandler):
    """
    A simple HTTP handler that can simulate delays and streaming.
    """

    def do_GET(self) -> None:
        if self.path == "/delay":
            time.sleep(2)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Delayed response")
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(3):
                self.wfile.write(b"5\r\nHello\r\n")
                time.sleep(0.1)
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")


@pytest.fixture(scope="module")  # type: ignore[misc]
def mock_server() -> Generator[str, None, None]:
    """
    Starts a background HTTP server for testing requests/urllib3 integration.
    Returns the base URL of the server.
    """
    server = HTTPServer(("localhost", 0), MockServerHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    base_url = f"http://localhost:{server.server_port}"
    yield base_url

    server.shutdown()
    thread.join()


def test_urllib3_version() -> None:
    """Verify that the loaded urllib3 version is at least 2.6.3."""
    assert urllib3.__version__ >= "2.6.3"


def test_requests_integration_basic(mock_server: str) -> None:
    """Verify basic GET request works with the new urllib3."""
    response = requests.get(f"{mock_server}/")
    assert response.status_code == 200
    assert response.text == "OK"


def test_requests_integration_streaming(mock_server: str) -> None:
    """
    Verify streaming response works.
    This is relevant because CVE-2026-21441 was related to streaming API.
    """
    response = requests.get(f"{mock_server}/stream", stream=True)
    assert response.status_code == 200
    chunks = list(response.iter_content(chunk_size=None))
    assert len(chunks) > 0
    assert b"".join(chunks) == b"HelloHelloHello"


def test_requests_integration_timeout(mock_server: str) -> None:
    """Verify timeout handling (uses urllib3 timeout logic)."""
    with pytest.raises(ReadTimeout):
        requests.get(f"{mock_server}/delay", timeout=0.5)


def test_requests_connection_error() -> None:
    """Verify connection error handling."""
    # Connecting to a port that is likely closed
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get("http://localhost:1", timeout=0.1)
