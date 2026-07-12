from dataclasses import dataclass


@dataclass(frozen=True)
class Location:
    file_path: str
    line: int
    column: int