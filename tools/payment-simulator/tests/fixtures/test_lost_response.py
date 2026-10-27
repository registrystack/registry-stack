import httpx
import pytest

from tests.fixtures.lost_response import lost_response_relay


def test_relay_refuses_a_path_it_was_not_given() -> None:
    # Nothing listens on the target: the relay refuses before it forwards anything.
    with lost_response_relay("http://127.0.0.1:9", "/rtpRequest") as (relay_url, receipt):
        assert relay_url.endswith("/rtpRequest")
        with pytest.raises(httpx.TransportError):
            httpx.post(
                relay_url.removesuffix("/rtpRequest") + "/elsewhere",
                content=b"{}",
                timeout=2.0,
            )
        assert receipt.event.wait(timeout=5), "relay did not record the refused request"
        assert isinstance(receipt.error, AssertionError)
        assert str(receipt.error) == "relay serves /rtpRequest, not /elsewhere"
        assert receipt.status_code is None
