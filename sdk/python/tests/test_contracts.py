"""Public Python SDK conformance tests using only the standard library."""

from __future__ import annotations

import unittest

from agentmemory_adapter_sdk import ProbeRequest, ProbeResponse

REQUEST = (
    b'{"capabilities":["agent.event.capture"],"challenge":"challenge-1",'
    b'"kind":"agent","manifest_digest":"'
    + b"a" * 64
    + b'","package_digest":"'
    + b"b" * 64
    + b'","protocol":"1.0","schema_version":1}'
)


class ProbeContractTests(unittest.TestCase):
    """Prove exact echo behavior and strict parsing for external authors."""

    def test_round_trip_preserves_every_security_coordinate(self) -> None:
        """A valid request produces the canonical seven-field response."""
        request = ProbeRequest.from_json(REQUEST)

        assert ProbeResponse(request).to_json() == (
            b'{"capabilities":["agent.event.capture"],"challenge":"challenge-1",'
            b'"manifest_digest":"'
            + b"a" * 64
            + b'","package_digest":"'
            + b"b" * 64
            + b'","protocol":"1.0","schema_version":1,"status":"passed"}'
        )

    def test_duplicate_unknown_and_noncanonical_requests_are_rejected(self) -> None:
        """Ambiguous public input fails closed before adapter execution."""
        invalid = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"unknown":true}',
            REQUEST.replace(
                b'"capabilities":["agent.event.capture"]',
                b'"capabilities":["provider.rerank","provider.embed"]',
            ),
        )
        for value in invalid:
            rejected = False
            try:
                ProbeRequest.from_json(value)
            except TypeError, ValueError:
                rejected = True
            assert rejected, value


if __name__ == "__main__":
    unittest.main()
