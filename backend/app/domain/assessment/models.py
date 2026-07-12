from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Assessment:
    """Represents a security assessment record."""

    id: str
    title: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
