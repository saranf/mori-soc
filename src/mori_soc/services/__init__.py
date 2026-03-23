"""Service helpers for Phase 1 query execution."""

from .ingestion import CollectorIngestionService, IngestionReport
from .normalization import EnvelopeEntityMapper
from .query_catalog import PHASE1_QUERY_CATALOG, TemplateQuery, get_template_query
from .query_service import InMemoryQueryStore, QueryService
from .risk_score import ALERT_WEIGHTS, MAX_RISK_SCORE, VULN_WEIGHTS, RiskScoreCalculator
from .views import (
    HostRiskSummaryRow,
    HostTimelineEntry,
    LatestHostStatusRow,
    host_risk_summary_view,
    host_timeline_view,
    latest_host_status_view,
)

__all__ = [
    "CollectorIngestionService",
    "EnvelopeEntityMapper",
    "IngestionReport",
    "TemplateQuery",
    "PHASE1_QUERY_CATALOG",
    "get_template_query",
    "InMemoryQueryStore",
    "QueryService",
    "RiskScoreCalculator",
    "ALERT_WEIGHTS",
    "VULN_WEIGHTS",
    "MAX_RISK_SCORE",
    # views
    "LatestHostStatusRow",
    "HostRiskSummaryRow",
    "HostTimelineEntry",
    "latest_host_status_view",
    "host_risk_summary_view",
    "host_timeline_view",
]