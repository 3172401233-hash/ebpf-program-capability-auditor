"""Python eBPF 程序能力审计器。

对 eBPF 指令序列做静态能力审计: helper 调用、上下文字段偏移、
map 读写范围、越界跳转、特权/版本/白名单策略。
本工具不替代内核 verifier, 详见 README。
"""

from .auditor import Auditor, MapPermission
from .report import AuditReport, Finding, ERROR, WARNING, INFO
from .instruction import decode, encode, encode_ld_imm64

__all__ = [
    "Auditor",
    "MapPermission",
    "AuditReport",
    "Finding",
    "ERROR",
    "WARNING",
    "INFO",
    "decode",
    "encode",
    "encode_ld_imm64",
]
