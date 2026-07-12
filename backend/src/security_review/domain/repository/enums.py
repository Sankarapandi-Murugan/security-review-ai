from enum import Enum


class RepositoryStatus(str, Enum):
    CREATED = "created"
    READY = "ready"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class Language(str, Enum):
    JAVA = "java"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    CSHARP = "csharp"
    KOTLIN = "kotlin"


class BuildSystem(str, Enum):
    MAVEN = "maven"
    GRADLE = "gradle"
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    PIP = "pip"
    POETRY = "poetry"
    GO = "go"
    CARGO = "cargo"
    UNKNOWN = "unknown"