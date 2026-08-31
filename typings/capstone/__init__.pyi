from collections.abc import Generator

CS_ARCH_ARM: int
CS_ARCH_ARM64: int
CS_ARCH_MIPS: int
CS_ARCH_X86: int
CS_ARCH_PPC: int
CS_ARCH_SPARC: int
CS_ARCH_SYSZ: int
CS_ARCH_XCORE: int
CS_ARCH_M68K: int
CS_ARCH_TMS320C64X: int
CS_ARCH_M680X: int
CS_ARCH_EVM: int
CS_ARCH_MOS65XX: int
CS_ARCH_WASM: int
CS_ARCH_BPF: int
CS_ARCH_RISCV: int
CS_ARCH_SH: int
CS_ARCH_TRICORE: int
CS_ARCH_MAX: int
CS_ARCH_ALL: int

CS_MODE_LITTLE_ENDIAN: int
CS_MODE_ARM: int
CS_MODE_16: int
CS_MODE_32: int
CS_MODE_64: int
CS_MODE_THUMB: int
CS_MODE_MCLASS: int
CS_MODE_V8: int
CS_MODE_MICRO: int
CS_MODE_MIPS3: int
CS_MODE_MIPS32R6: int
CS_MODE_MIPS2: int
CS_MODE_V9: int
CS_MODE_QPX: int
CS_MODE_SPE: int
CS_MODE_BOOKE: int
CS_MODE_PS: int
CS_MODE_BIG_ENDIAN: int
CS_MODE_MIPS32: int
CS_MODE_MIPS64: int
CS_MODE_RISCV32: int
CS_MODE_RISCV64: int
CS_MODE_RISCVC: int

CS_OPT_SYNTAX: int
CS_OPT_DETAIL: int
CS_OPT_MODE: int
CS_OPT_MEM: int
CS_OPT_SKIPDATA: int
CS_OPT_SKIPDATA_SETUP: int
CS_OPT_MNEMONIC: int
CS_OPT_UNSIGNED: int

CS_OPT_OFF: int
CS_OPT_ON: int

CS_OPT_SYNTAX_DEFAULT: int
CS_OPT_SYNTAX_INTEL: int
CS_OPT_SYNTAX_ATT: int
CS_OPT_SYNTAX_NOREGNAME: int
CS_OPT_SYNTAX_MASM: int
CS_OPT_SYNTAX_MOTOROLA: int

CS_ERR_OK: int
CS_ERR_MEM: int
CS_ERR_ARCH: int
CS_ERR_HANDLE: int
CS_ERR_CSH: int
CS_ERR_MODE: int
CS_ERR_OPTION: int
CS_ERR_DETAIL: int
CS_ERR_MEMSETUP: int
CS_ERR_VERSION: int
CS_ERR_DIET: int
CS_ERR_SKIPDATA: int
CS_ERR_X86_ATT: int
CS_ERR_X86_INTEL: int
CS_ERR_X86_MASM: int

CS_SUPPORT_DIET: int
CS_SUPPORT_X86_REDUCE: int

CS_API_MAJOR: int
CS_API_MINOR: int

class CsError(Exception):
    errno: int
    def __init__(self, errno: int) -> None: ...

class CsInsn:
    @property
    def id(self) -> int: ...
    @property
    def address(self) -> int: ...
    @property
    def size(self) -> int: ...
    @property
    def bytes(self) -> bytearray: ...
    @property
    def mnemonic(self) -> str: ...
    @property
    def op_str(self) -> str: ...
    @property
    def regs_read(self) -> list[int]: ...
    @property
    def regs_write(self) -> list[int]: ...
    @property
    def groups(self) -> list[int]: ...
    def reg_name(self, reg_id: int, default: str | None = None) -> str: ...
    def insn_name(self) -> str: ...
    def group_name(self, group_id: int) -> str: ...
    def group(self, group_id: int) -> bool: ...
    def reg_read(self, reg_id: int) -> bool: ...
    def reg_write(self, reg_id: int) -> bool: ...
    def operand_count(self, op_type: int) -> int: ...

class Cs:
    arch: int
    def __init__(self, arch: int, mode: int) -> None: ...
    @property
    def diet(self) -> bool: ...
    @property
    def x86_reduce(self) -> bool: ...
    @property
    def syntax(self) -> int | None: ...
    @syntax.setter
    def syntax(self, style: int) -> None: ...
    @property
    def detail(self) -> bool: ...
    @detail.setter
    def detail(self, opt: bool) -> None: ...
    @property
    def skipdata(self) -> bool: ...
    @skipdata.setter
    def skipdata(self, opt: bool) -> None: ...
    @property
    def skipdata_mnem(self) -> str: ...
    @skipdata_mnem.setter
    def skipdata_mnem(self, mnem: str) -> None: ...
    def disasm(self, code: bytes, offset: int, count: int = 0) -> Generator[CsInsn, None, None]: ...
    def disasm_lite(self, code: bytes, offset: int, count: int = 0) -> Generator[tuple[int, int, str, str], None, None]: ...

def cs_version() -> tuple[int, int, int]: ...
def version_bind() -> tuple[int, int]: ...
def debug() -> int: ...
def cs_support(query: int) -> bool: ...
def cs_disasm_quick(arch: int, mode: int, code: bytes, offset: int, count: int = 0) -> Generator[CsInsn, None, None]: ...
