from enum import Enum

from pydantic import BaseModel


class EnrichmentLevel(str, Enum):
    RAW = "RAW"
    TAGGED = "TAGGED"
    LINKED = "LINKED"


class KnowledgeArtifact(BaseModel):  # type: ignore[misc]
    enrichment_level: EnrichmentLevel
    source_urn: str
