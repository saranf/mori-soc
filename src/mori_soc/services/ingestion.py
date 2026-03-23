from __future__ import annotations

from dataclasses import dataclass

from mori_soc.collectors.base import BaseCollector
from mori_soc.repositories.base import BaseRepository

from .normalization import EnvelopeEntityMapper


@dataclass(slots=True)
class IngestionReport:
    records_collected: int = 0
    envelopes_normalized: int = 0
    entities_saved: int = 0


class CollectorIngestionService:
    def __init__(self, mapper: EnvelopeEntityMapper, repository: BaseRepository) -> None:
        self.mapper = mapper
        self.repository = repository

    def ingest_collector(self, collector: BaseCollector) -> IngestionReport:
        report = IngestionReport()
        for record in collector.collect():
            report.records_collected += 1
            for envelope in collector.normalize(record):
                report.envelopes_normalized += 1
                for entity in self.mapper.map_envelope(envelope):
                    self.repository.save(entity)
                    report.entities_saved += 1
        return report