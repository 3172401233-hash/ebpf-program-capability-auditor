"""审计报告数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field

ERROR = "error"
WARNING = "warning"
INFO = "info"


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    message: str
    insn_index: int | None = None

    def __str__(self) -> str:
        loc = f"insn[{self.insn_index}] " if self.insn_index is not None else ""
        return f"[{self.severity}] {self.category}: {loc}{self.message}"


@dataclass
class MapAccess:
    map_id: int
    reads: int = 0
    writes: int = 0
    max_read_end: int = 0
    max_write_end: int = 0


@dataclass
class AuditReport:
    prog_type: str
    attach_type: str
    findings: list[Finding] = field(default_factory=list)
    helpers_used: list[str] = field(default_factory=list)
    map_accesses: dict[int, MapAccess] = field(default_factory=dict)
    context_fields_read: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == ERROR for f in self.findings)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == WARNING]

    def add(self, severity, category, message, insn_index=None):
        self.findings.append(Finding(severity, category, message, insn_index))

    def summary(self) -> str:
        lines = [
            f"program={self.prog_type} attach={self.attach_type} "
            f"ok={self.ok} errors={len(self.errors)} warnings={len(self.warnings)}"
        ]
        lines.extend(str(f) for f in self.findings)
        if self.helpers_used:
            lines.append("helpers: " + ", ".join(self.helpers_used))
        for mid, acc in sorted(self.map_accesses.items()):
            lines.append(
                f"map {mid}: reads={acc.reads} writes={acc.writes} "
                f"max_read_end={acc.max_read_end} max_write_end={acc.max_write_end}"
            )
        return "\n".join(lines)
