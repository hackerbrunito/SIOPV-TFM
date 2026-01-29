"""External API adapters for SIOPV."""

from siopv.adapters.external_apis.trivy_parser import TrivyParser, parse_trivy_report

__all__ = ["TrivyParser", "parse_trivy_report"]
