from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from trading_lab.api_auth import ApiKeyVerifier
from trading_lab.fastapi_service import create_fastapi_app


class FakeApplication:
    def health(self):
        return {"healthy": True}

    def status(self):
        return {
            "mode": "OBSERVE_ONLY"
        }

    def research_metrics(self):
        return {
            "minimum_evidence_sample": 30,
            "strategies": [],
            "groups": [],
        }

    def save_hypothesis(
        self,
        hypothesis_id: str,
        thesis: str,
    ):
        return {
            "recorded": True,
            "hypothesis_id": hypothesis_id,
        }


class ResearchAuthSplitTests(
    unittest.TestCase
):
    GATEWAY_KEY = "G" * 43
    RESEARCH_KEY = "R" * 43

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)

        gateway_path = (
            root / "gateway.key"
        )

        research_path = (
            root / "research.key"
        )

        gateway_path.write_text(
            self.GATEWAY_KEY,
            encoding="ascii",
        )

        research_path.write_text(
            self.RESEARCH_KEY,
            encoding="ascii",
        )

        self.gateway_headers = {
            "X-AUTOMATON-KEY":
                self.GATEWAY_KEY
        }

        self.research_headers = {
            "X-AUTOMATON-RESEARCH-KEY":
                self.RESEARCH_KEY
        }

        api = create_fastapi_app(
            FakeApplication(),
            ApiKeyVerifier(
                gateway_path
            ),
            research_verifier=ApiKeyVerifier(
                research_path
            ),
        )

        self.client = TestClient(
            api
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_research_key_can_access_only_research_routes(
        self,
    ) -> None:
        response = self.client.get(
            "/v1/research/metrics",
            headers=self.research_headers,
        )

        self.assertEqual(
            200,
            response.status_code,
        )

        response = self.client.post(
            "/v1/research/hypotheses",
            headers=self.research_headers,
            json={
                "hypothesis_id": "h1",
                "thesis": "test thesis",
            },
        )

        self.assertEqual(
            200,
            response.status_code,
        )

        blocked = self.client.get(
            "/v1/status",
            headers=self.research_headers,
        )

        self.assertEqual(
            401,
            blocked.status_code,
        )

        self.assertEqual(
            "invalid_gateway_key",
            blocked.json()["error"],
        )

    def test_gateway_key_cannot_cross_into_research_namespace(
        self,
    ) -> None:
        response = self.client.get(
            "/v1/research/metrics",
            headers=self.gateway_headers,
        )

        self.assertEqual(
            401,
            response.status_code,
        )

        self.assertEqual(
            "invalid_research_key",
            response.json()["error"],
        )

    def test_research_key_cannot_reach_trade_namespace(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/trade/propose",
            headers=self.research_headers,
            json={},
        )

        self.assertEqual(
            401,
            response.status_code,
        )

        self.assertEqual(
            "invalid_gateway_key",
            response.json()["error"],
        )

    def test_mixed_credentials_fail_closed(
        self,
    ) -> None:
        both = {
            **self.gateway_headers,
            **self.research_headers,
        }

        research = self.client.get(
            "/v1/research/metrics",
            headers=both,
        )

        self.assertEqual(
            401,
            research.status_code,
        )

        self.assertEqual(
            "invalid_research_key",
            research.json()["error"],
        )

        gateway = self.client.get(
            "/v1/status",
            headers=both,
        )

        self.assertEqual(
            401,
            gateway.status_code,
        )

        self.assertEqual(
            "invalid_gateway_key",
            gateway.json()["error"],
        )

    def test_legacy_single_key_mode_remains_backward_compatible(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = (
                Path(directory)
                / "gateway.key"
            )

            key_path.write_text(
                self.GATEWAY_KEY,
                encoding="ascii",
            )

            legacy = TestClient(
                create_fastapi_app(
                    FakeApplication(),
                    ApiKeyVerifier(
                        key_path
                    ),
                )
            )

            response = legacy.get(
                "/v1/research/metrics",
                headers=self.gateway_headers,
            )

            self.assertEqual(
                200,
                response.status_code,
            )


if __name__ == "__main__":
    unittest.main()