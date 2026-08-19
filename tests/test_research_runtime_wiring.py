from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ResearchRuntimeWiringTests(
    unittest.TestCase
):
    def test_gateway_runtime_uses_dedicated_research_verifier(
        self,
    ) -> None:
        source = (
            ROOT
            / "trading_lab"
            / "service.py"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "RESEARCH_API_KEY_PATH = Path(",
            source,
        )

        self.assertIn(
            r'r"\ipc\research.key"',
            source,
        )

        self.assertIn(
            "research_verifier = ApiKeyVerifier(",
            source,
        )

        self.assertIn(
            "research_verifier=research_verifier",
            source,
        )

    def test_research_key_is_not_added_to_trading_config_schema(
        self,
    ) -> None:
        source = (
            ROOT
            / "trading_lab"
            / "config.py"
        ).read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "research_key_path",
            source,
        )


    def test_agent_setup_never_requires_gateway_credential(
        self,
    ) -> None:
        source = (
            ROOT
            / "src"
            / "trading"
            / "setup.ts"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'readObservationApiKey',
            source,
        )

        self.assertIn(
            'readResearchApiKey',
            source,
        )

        self.assertNotIn(
            'readGatewayApiKey',
            source,
        )

        self.assertNotIn(
            '"./gateway-auth.js"',
            source,
        )

    def test_agent_launcher_exposes_only_observation_and_research_credentials(
        self,
    ) -> None:
        source = (
            ROOT
            / "scripts"
            / "start_automaton.ps1"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            r"C:\ProgramData\AutomatonMT5Lab\ipc\observation.key",
            source,
        )

        self.assertIn(
            r"C:\ProgramData\AutomatonMT5Lab\ipc\research.key",
            source,
        )

        self.assertNotIn(
            "automaton.key",
            source,
        )

        self.assertIn(
            "$env:AUTOMATON_MT5_OBSERVATION_API_KEY_FILE",
            source,
        )

        self.assertIn(
            "$env:AUTOMATON_MT5_RESEARCH_API_KEY_FILE",
            source,
        )

        self.assertNotIn(
            "$env:AUTOMATON_MT5_API_KEY_FILE =",
            source,
        )

        self.assertIn(
            "Env:AUTOMATON_MT5_API_KEY_FILE",
            source,
        )

        self.assertIn(
            "must be absent",
            source,
        )


if __name__ == "__main__":
    unittest.main()
