"""eBPF 指令解码与编码。

eBPF 指令固定 8 字节:
  byte 0    : opcode
  byte 1    : 低 4 位 dst_reg, 高 4 位 src_reg
  byte 2-3  : 有符号偏移 offset (小端)
  byte 4-7  : 有符号立即数 imm (小端)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

INSN_SIZE = 8

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_IMM = 0x00
BPF_MEM = 0x60
BPF_DW = 0x18

BPF_JA = 0x00
BPF_CALL = 0x80
BPF_EXIT = 0x90

BPF_MOV = 0xB0
BPF_K = 0x00
BPF_X = 0x08

BPF_PSEUDO_MAP_FD = 1
BPF_PSEUDO_MAP_VALUE = 2
BPF_PSEUDO_CALL = 1

_SIZE_TABLE = {0: 4, 1: 2, 2: 1, 3: 8}

_JCC_CODES = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0}


@dataclass(frozen=True)
class Instruction:
    index: int
    opcode: int
    dst: int
    src: int
    off: int
    imm: int

    @property
    def cls(self) -> int:
        return self.opcode & 0x07

    @property
    def mode(self) -> int:
        return self.opcode & 0xE0

    @property
    def size(self) -> int:
        return _SIZE_TABLE[(self.opcode >> 3) & 0x03]

    @property
    def is_ldx_mem(self) -> bool:
        return self.cls == BPF_LDX and self.mode == BPF_MEM

    @property
    def is_stx_mem(self) -> bool:
        return self.cls == BPF_STX and self.mode == BPF_MEM

    @property
    def is_call(self) -> bool:
        return self.cls == BPF_JMP and (self.opcode & 0xF0) == BPF_CALL

    @property
    def is_exit(self) -> bool:
        return self.cls == BPF_JMP and (self.opcode & 0xF0) == BPF_EXIT

    @property
    def is_ld_imm64(self) -> bool:
        return self.opcode == (BPF_LD | BPF_IMM | BPF_DW)

    @property
    def is_mov_reg(self) -> bool:
        return (
            self.cls in (BPF_ALU, BPF_ALU64)
            and (self.opcode & 0xF0) == BPF_MOV
            and (self.opcode & 0x08) == BPF_X
        )

    @property
    def is_jump(self) -> bool:
        if self.cls not in (BPF_JMP, BPF_JMP32):
            return False
        code = self.opcode & 0xF0
        return code == BPF_JA or code in _JCC_CODES

    @property
    def is_unconditional_ja(self) -> bool:
        return self.cls == BPF_JMP and (self.opcode & 0xF0) == BPF_JA

    @property
    def jump_target(self) -> int:
        return self.index + 1 + self.off


def decode(data: bytes):
    """解码字节流, 返回 (指令列表, 截断的剩余字节数)。"""
    truncated = len(data) % INSN_SIZE
    insns = []
    for i in range(0, len(data) - truncated, INSN_SIZE):
        opcode, regs, off, imm = struct.unpack_from("<BBhi", data, i)
        insns.append(
            Instruction(
                index=i // INSN_SIZE,
                opcode=opcode,
                dst=regs & 0x0F,
                src=(regs >> 4) & 0x0F,
                off=off,
                imm=imm,
            )
        )
    return insns, truncated


def encode(opcode, dst=0, src=0, off=0, imm=0):
    """编码单条指令, 供测试与调用方构造程序。"""
    return struct.pack("<BBhi", opcode, (src << 4) | (dst & 0x0F), off, imm)


def encode_ld_imm64(dst, src, imm):
    """编码 ld_imm64 (占两个指令槽)。"""
    return encode(BPF_LD | BPF_IMM | BPF_DW, dst=dst, src=src, imm=imm) + encode(0)
