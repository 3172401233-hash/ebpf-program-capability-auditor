"""eBPF 程序能力审计器核心。

对解码后的指令做线性静态扫描, 结合简化的寄存器状态跟踪
(ctx 指针 / map 引用 / map 值指针), 检查:
  - helper 调用: 未知 helper、白名单、特权要求、内核版本
  - 上下文字段偏移是否属于当前程序/attach 类型的上下文布局
  - map 读写权限与值访问的最大范围
  - 跳转目标越界、缺少 exit、截断指令
  - 复杂尾调用与静态子程序调用显式报告
"""

from __future__ import annotations

from dataclasses import dataclass

from . import instruction as I
from .report import AuditReport, MapAccess, ERROR, WARNING, INFO
from .spec import HELPERS, PROG_TYPES, ATTACH_TYPES, CONTEXTS

DEFAULT_KERNEL = (6, 6)


@dataclass(frozen=True)
class MapPermission:
    map_id: int
    readable: bool = True
    writable: bool = True
    key_size: int = 4
    value_size: int = 8


class Auditor:
    def __init__(
        self,
        prog_type: str,
        attach_type: str,
        helper_whitelist=None,
        map_permissions=None,
        kernel_version=DEFAULT_KERNEL,
        unprivileged: bool = False,
    ):
        self.prog_type = prog_type
        self.attach_type = attach_type
        self.kernel_version = tuple(kernel_version)
        self.unprivileged = unprivileged
        self.whitelist = self._normalize_whitelist(helper_whitelist)
        self.maps: dict[int, MapPermission] = {}
        for perm in map_permissions or []:
            self.maps[perm.map_id] = perm

    @staticmethod
    def _normalize_whitelist(whitelist):
        if whitelist is None:
            return None
        ids = set()
        for item in whitelist:
            if isinstance(item, int):
                ids.add(item)
                continue
            for hid, spec in HELPERS.items():
                if spec.name == item or spec.name == f"bpf_{item}":
                    ids.add(hid)
                    break
            else:
                raise ValueError(f"白名单中的未知 helper: {item}")
        return ids

    def audit(self, code: bytes) -> AuditReport:
        report = AuditReport(prog_type=self.prog_type, attach_type=self.attach_type)
        insns, truncated = I.decode(code)
        if truncated:
            report.add(
                ERROR, "truncated",
                f"指令流末尾有 {truncated} 字节不足一条指令 (8 字节), 程序被截断",
            )
        if not insns:
            report.add(ERROR, "empty", "程序不包含任何完整指令")
            return report

        if not self._check_types(report):
            return report
        self._check_jumps(insns, report)
        self._scan(insns, report)
        return report

    def _check_types(self, report) -> bool:
        ok = True
        prog = PROG_TYPES.get(self.prog_type)
        if prog is None:
            report.add(ERROR, "prog_type", f"未知程序类型: {self.prog_type}")
            return False
        if self.kernel_version < prog.min_kernel:
            report.add(
                ERROR, "kernel_version",
                f"程序类型 {self.prog_type} 需要内核 >= "
                f"{prog.min_kernel[0]}.{prog.min_kernel[1]}, "
                f"当前 {self.kernel_version[0]}.{self.kernel_version[1]}",
            )
            ok = False
        attach = ATTACH_TYPES.get(self.attach_type)
        if attach is None:
            report.add(ERROR, "attach_type", f"未知 attach 类型: {self.attach_type}")
            ok = False
        else:
            if self.kernel_version < attach.min_kernel:
                report.add(
                    ERROR, "kernel_version",
                    f"attach 类型 {self.attach_type} 需要内核 >= "
                    f"{attach.min_kernel[0]}.{attach.min_kernel[1]}",
                )
                ok = False
            if self.attach_type not in prog.allowed_attach:
                report.add(
                    ERROR, "attach_type",
                    f"attach 类型 {self.attach_type} 不适用于程序类型 "
                    f"{self.prog_type} (允许: {sorted(prog.allowed_attach)})",
                )
                ok = False
        return ok

    def _check_jumps(self, insns, report):
        n = len(insns)
        for insn in insns:
            if insn.is_jump:
                target = insn.jump_target
                if not 0 <= target < n:
                    report.add(
                        ERROR, "jump",
                        f"跳转目标 {target} 越界 (程序共 {n} 条指令)",
                        insn.index,
                    )
        if not any(i.is_exit for i in insns):
            report.add(ERROR, "exit", "程序缺少 exit 指令")
        elif not (insns[-1].is_exit or insns[-1].is_unconditional_ja):
            report.add(
                WARNING, "exit",
                "最后一条指令不是 exit/ja, 可能落入填充数据",
                insns[-1].index,
            )

    def _scan(self, insns, report):
        prog = PROG_TYPES[self.prog_type]
        ctx_spec = CONTEXTS[prog.context]
        regs: dict[int, tuple] = {1: ("ctx",)}
        jump_targets = {i.jump_target for i in insns if i.is_jump}
        skip_next = False

        for insn in insns:
            if skip_next:
                skip_next = False
                continue
            if insn.index in jump_targets:
                regs.clear()

            if insn.is_ld_imm64:
                self._handle_ld_imm64(insn, regs, report)
                skip_next = True
                continue
            if insn.is_call:
                self._handle_call(insn, regs, report)
                continue
            if insn.is_exit:
                regs.clear()
                continue
            if insn.is_mov_reg:
                regs[insn.dst] = regs.get(insn.src, ("scalar",))
                continue
            if insn.is_ldx_mem:
                self._check_mem_read(insn, regs, report, ctx_spec)
                regs[insn.dst] = ("scalar",)
                continue
            if insn.is_stx_mem:
                self._check_mem_write(insn, regs, report)
                continue
            if insn.cls in (I.BPF_ALU, I.BPF_ALU64):
                regs[insn.dst] = ("scalar",)
                continue
            if insn.is_jump:
                regs.clear()

    def _handle_ld_imm64(self, insn, regs, report):
        if insn.src == I.BPF_PSEUDO_MAP_FD:
            if insn.imm not in self.maps:
                report.add(
                    WARNING, "map",
                    f"引用了未声明权限的 map id {insn.imm}, 按不可读写处理",
                    insn.index,
                )
            regs[insn.dst] = ("map", insn.imm)
        elif insn.src == I.BPF_PSEUDO_MAP_VALUE:
            perm = self.maps.get(insn.imm)
            limit = perm.value_size if perm else 0
            regs[insn.dst] = ("mapval", insn.imm, limit)
        else:
            regs[insn.dst] = ("scalar",)

    def _handle_call(self, insn, regs, report):
        if insn.src == I.BPF_PSEUDO_CALL:
            report.add(
                INFO, "call",
                "静态子程序调用 (BPF_PSEUDO_CALL), 本审计器不跟随子程序控制流",
                insn.index,
            )
            regs[0] = ("scalar",)
            for r in range(1, 6):
                regs.pop(r, None)
            return

        helper = HELPERS.get(insn.imm)
        if helper is None:
            report.add(ERROR, "helper", f"未知 helper id {insn.imm}", insn.index)
        else:
            if self.whitelist is not None and helper.id not in self.whitelist:
                report.add(
                    ERROR, "helper",
                    f"helper {helper.name} 不在白名单中", insn.index,
                )
            if helper.privileged and self.unprivileged:
                report.add(
                    ERROR, "privilege",
                    f"非特权程序调用了高权限 helper {helper.name} "
                    f"(需要 CAP_SYS_ADMIN/CAP_PERFMON 等)", insn.index,
                )
            if self.kernel_version < helper.min_kernel:
                report.add(
                    ERROR, "kernel_version",
                    f"helper {helper.name} 需要内核 >= "
                    f"{helper.min_kernel[0]}.{helper.min_kernel[1]}, "
                    f"当前 {self.kernel_version[0]}.{self.kernel_version[1]}",
                    insn.index,
                )
            if helper.tail_call:
                report.add(
                    WARNING, "tail_call",
                    f"复杂尾调用 {helper.name}: 目标程序位于 prog_array map 中, "
                    f"审计器无法跟随; 需另行确认目标程序能力与 33 层深度限制",
                    insn.index,
                )
            if helper.map_op:
                self._check_map_helper(insn, helper, regs, report)
            if helper.name not in report_helpers(report):
                report.helpers_used.append(helper.name)
            if helper.id == 1:
                state = regs.get(1)
                if state and state[0] == "map":
                    perm = self.maps.get(state[1])
                    limit = perm.value_size if perm else 0
                    regs[0] = ("mapval", state[1], limit)
                else:
                    regs[0] = ("scalar",)
            else:
                regs[0] = ("scalar",)
        for r in range(1, 6):
            regs.pop(r, None)

    def _check_map_helper(self, insn, helper, regs, report):
        state = regs.get(1)
        if not state or state[0] != "map":
            report.add(
                WARNING, "map",
                f"{helper.name} 的 map 参数无法静态确定, 跳过权限检查",
                insn.index,
            )
            return
        map_id = state[1]
        perm = self.maps.get(map_id)
        acc = report.map_accesses.setdefault(map_id, MapAccess(map_id))
        if helper.map_op == "read":
            acc.reads += 1
            if perm is not None and not perm.readable:
                report.add(
                    ERROR, "map",
                    f"对只写 map {map_id} 调用读操作 {helper.name}", insn.index,
                )
        else:
            acc.writes += 1
            if perm is not None and not perm.writable:
                report.add(
                    ERROR, "map",
                    f"非法 map 写入: map {map_id} 为只读, "
                    f"却调用了 {helper.name}", insn.index,
                )

    def _check_mem_read(self, insn, regs, report, ctx_spec):
        state = regs.get(insn.src)
        if state is None:
            return
        if state[0] == "ctx":
            field = ctx_spec.find(insn.off, insn.size)
            if field is None:
                report.add(
                    ERROR, "context",
                    f"上下文偏移 {insn.off} (大小 {insn.size}) 不属于 "
                    f"{self.prog_type}/{self.attach_type} 的上下文 "
                    f"{ctx_spec.name}", insn.index,
                )
            else:
                if self.kernel_version < field.min_kernel:
                    report.add(
                        ERROR, "kernel_version",
                        f"上下文字段 {ctx_spec.name}.{field.name} 需要内核 >= "
                        f"{field.min_kernel[0]}.{field.min_kernel[1]}",
                        insn.index,
                    )
                name = f"{ctx_spec.name}.{field.name}"
                if name not in report.context_fields_read:
                    report.context_fields_read.append(name)
        elif state[0] == "mapval":
            _, map_id, limit = state
            end = insn.off + insn.size
            acc = report.map_accesses.setdefault(map_id, MapAccess(map_id))
            acc.reads += 1
            acc.max_read_end = max(acc.max_read_end, end)
            perm = self.maps.get(map_id)
            if perm is not None and not perm.readable:
                report.add(
                    ERROR, "map",
                    f"对不可读 map {map_id} 的值做读访问", insn.index,
                )
            if insn.off < 0 or end > limit:
                report.add(
                    ERROR, "map",
                    f"map {map_id} 值读访问越界: 范围 [{insn.off}, {end}) "
                    f"超出 value_size {limit}", insn.index,
                )

    def _check_mem_write(self, insn, regs, report):
        state = regs.get(insn.dst)
        if state is None:
            return
        if state[0] == "ctx":
            report.add(
                ERROR, "context",
                f"向只读上下文偏移 {insn.off} 写入", insn.index,
            )
        elif state[0] == "mapval":
            _, map_id, limit = state
            end = insn.off + insn.size
            acc = report.map_accesses.setdefault(map_id, MapAccess(map_id))
            acc.writes += 1
            acc.max_write_end = max(acc.max_write_end, end)
            perm = self.maps.get(map_id)
            if perm is not None and not perm.writable:
                report.add(
                    ERROR, "map",
                    f"非法 map 写入: map {map_id} 为只读, "
                    f"却向值偏移 {insn.off} 写入 {insn.size} 字节",
                    insn.index,
                )
            if insn.off < 0 or end > limit:
                report.add(
                    ERROR, "map",
                    f"map {map_id} 值写访问越界: 范围 [{insn.off}, {end}) "
                    f"超出 value_size {limit}", insn.index,
                )


def report_helpers(report):
    return set(report.helpers_used)
