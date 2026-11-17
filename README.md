# ebpf-program-capability-auditor

Python eBPF 程序能力审计库。在加载前对 eBPF 指令序列做静态审计, 提前发现
"声明为非特权却调用高权限 helper"、"访问不属于当前 attach 类型的上下文字段"
等运行时才会暴露的问题。

## 功能

- **helper 调用检查**: 未知 helper id、白名单之外、非特权程序调用高权限 helper
  (如 `bpf_probe_read`)、helper 要求的最低内核版本
- **上下文字段偏移**: 按程序类型/attach 类型的上下文布局
  (`__sk_buff` / `xdp_md` / `bpf_sock` / tracepoint) 校验每次 `ldx` 的
  偏移与大小, 拒绝越界或跨上下文的字段访问及对只读上下文的写入
- **map 读写**: 依据声明的 `MapPermission` 检查 `map_lookup/update/delete` 等
  helper 的读写方向, 跟踪 map 值指针的读写最大范围并对照 `value_size` 报越界
- **控制流结构**: 跳转目标越界(含负偏移)、缺少 `exit`、截断指令
  (字节流长度不是 8 的倍数)
- **显式报告**: 复杂尾调用 (`bpf_tail_call`, 目标在 prog_array 中无法静态跟随)、
  静态子程序调用 (`BPF_PSEUDO_CALL`)、旧内核不支持的程序/attach 类型与 helper

## 用法

```python
from ebpf_audit import Auditor, MapPermission
from ebpf_audit.instruction import encode, encode_ld_imm64, BPF_PSEUDO_MAP_FD

code = b"".join([
    encode_ld_imm64(1, BPF_PSEUDO_MAP_FD, 1),  # r1 = map 1
    encode(0x85, imm=1),                       # call bpf_map_lookup_elem
    encode(0x61, dst=0, src=0, off=0),         # r0 = *(u32 *)(r0 + 0)
    encode(0x95),                              # exit
])

auditor = Auditor(
    prog_type="SOCKET_FILTER",
    attach_type="SOCKET_FILTER",
    helper_whitelist=["bpf_map_lookup_elem"],
    map_permissions=[MapPermission(1, readable=True, writable=False, value_size=8)],
    kernel_version=(5, 15),
    unprivileged=True,
)
report = auditor.audit(code)
print(report.ok)
print(report.summary())
```

运行测试:

```bash
python -m unittest
```

## 验证范围声明

本工具是**加载前的静态能力审计**, 不替代内核 verifier:

- 寄存器状态跟踪是线性、保守的(遇跳转汇合点即丢弃状态), 不做内核 verifier
  那样的全路径抽象解释, 无法推断指针算术后的精确范围
- 尾调用目标程序、动态 map 参数、子程序内部控制流不在分析范围内, 仅以
  warning/info 显式报告
- helper/上下文/版本表是常用子集, 与具体内核配置 (BTF、CO-RE、Kconfig)
  无关
- 审计通过不代表程序一定能通过内核 verifier; 审计失败也不代表内核一定拒绝,
  应以内核加载结果为准

## 目录结构

- `ebpf_audit/instruction.py` — 8 字节指令解码/编码
- `ebpf_audit/spec.py` — helper、程序类型、attach 类型、上下文布局规格表
- `ebpf_audit/auditor.py` — 审计器核心(策略检查 + 线性扫描)
- `ebpf_audit/report.py` — `Finding` / `AuditReport` 报告结构
- `tests/test_auditor.py` — socket filter、xdp、cgroup、非法 map 写入、
  截断指令等 27 个用例
