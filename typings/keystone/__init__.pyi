"""Partial type stub for the keystone-engine assembler.

Covers only the surface consumed by Intellicrack's x64dbg bridge
(``KS_ARCH_X86``, ``KS_MODE_32``, ``KS_MODE_64``, ``Ks`` class, and the
``Ks.asm`` method). The keystone-engine wheel does not ship type
information, so this bundled stub fills the strict-mode gap without
widening the type contract for unrelated keystone APIs.
"""

KS_ARCH_ARM: int
KS_ARCH_ARM64: int
KS_ARCH_MIPS: int
KS_ARCH_X86: int
KS_ARCH_PPC: int
KS_ARCH_SPARC: int
KS_ARCH_SYSTEMZ: int
KS_ARCH_HEXAGON: int
KS_ARCH_EVM: int
KS_ARCH_MAX: int

KS_MODE_LITTLE_ENDIAN: int
KS_MODE_BIG_ENDIAN: int
KS_MODE_ARM: int
KS_MODE_THUMB: int
KS_MODE_V8: int
KS_MODE_MICRO: int
KS_MODE_MIPS3: int
KS_MODE_MIPS32R6: int
KS_MODE_MIPS32: int
KS_MODE_MIPS64: int
KS_MODE_16: int
KS_MODE_32: int
KS_MODE_64: int
KS_MODE_PPC32: int
KS_MODE_PPC64: int
KS_MODE_QPX: int
KS_MODE_SPARC32: int
KS_MODE_SPARC64: int
KS_MODE_V9: int

KS_OPT_SYNTAX: int
KS_OPT_SYNTAX_INTEL: int
KS_OPT_SYNTAX_ATT: int
KS_OPT_SYNTAX_NASM: int
KS_OPT_SYNTAX_MASM: int
KS_OPT_SYNTAX_GAS: int
KS_OPT_SYNTAX_RADIX16: int

KS_ERR_OK: int
KS_ERR_NOMEM: int
KS_ERR_ARCH: int
KS_ERR_HANDLE: int
KS_ERR_MODE: int
KS_ERR_VERSION: int
KS_ERR_OPT_INVALID: int
KS_ERR_ASM: int
KS_ERR_ASM_EXPR_TOKEN: int
KS_ERR_ASM_DIRECTIVE_VALUE_RANGE: int
KS_ERR_ASM_DIRECTIVE_ID: int
KS_ERR_ASM_DIRECTIVE_TOKEN: int
KS_ERR_ASM_DIRECTIVE_STR: int
KS_ERR_ASM_DIRECTIVE_COMMA: int
KS_ERR_ASM_DIRECTIVE_RELOC_NAME: int
KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN: int
KS_ERR_ASM_DIRECTIVE_FPOINT: int
KS_ERR_ASM_DIRECTIVE_UNKNOWN: int
KS_ERR_ASM_DIRECTIVE_EQU: int
KS_ERR_ASM_DIRECTIVE_INVALID: int
KS_ERR_ASM_VARIANT_INVALID: int
KS_ERR_ASM_EXPR_BRACKET: int
KS_ERR_ASM_SYMBOL_MODIFIER: int
KS_ERR_ASM_SYMBOL_REDEFINED: int
KS_ERR_ASM_SYMBOL_MISSING: int
KS_ERR_ASM_RPAREN: int
KS_ERR_ASM_STAT_TOKEN: int
KS_ERR_ASM_UNSUPPORTED: int
KS_ERR_ASM_MACRO_TOKEN: int
KS_ERR_ASM_MACRO_PAREN: int
KS_ERR_ASM_MACRO_EQU: int
KS_ERR_ASM_MACRO_ARGS: int
KS_ERR_ASM_MACRO_LEVELS_EXCEED: int
KS_ERR_ASM_MACRO_STR: int
KS_ERR_ASM_MACRO_INVALID: int
KS_ERR_ASM_ESC_BACKSLASH: int
KS_ERR_ASM_ESC_OCTAL: int
KS_ERR_ASM_ESC_SEQUENCE: int
KS_ERR_ASM_ESC_STR: int
KS_ERR_ASM_TOKEN_INVALID: int
KS_ERR_ASM_INSN_UNSUPPORTED: int
KS_ERR_ASM_FIXUP_INVALID: int
KS_ERR_ASM_LABEL_INVALID: int
KS_ERR_ASM_FRAGMENT_INVALID: int
KS_ERR_ASM_INVALIDOPERAND: int
KS_ERR_ASM_MISSINGFEATURE: int
KS_ERR_ASM_MNEMONICFAIL: int


class KsError(Exception):
    """Exception raised by ``Ks`` operations on assembly failure."""

    errno: int
    stat_count: int | None

    def __init__(self, errno: int, count: int | None = ..., addr: int | None = ...) -> None: ...

    def get_asm_count(self) -> int | None: ...


class Ks:
    """Keystone assembler engine bound to a specific architecture and mode."""

    arch: int
    mode: int
    syntax: int

    def __init__(self, arch: int, mode: int) -> None: ...

    def asm(
        self,
        string: str | bytes,
        addr: int = ...,
        as_bytes: bool = ...,
    ) -> tuple[list[int] | bytes | None, int]:
        """Assemble ``string`` at ``addr``.

        Returns:
            Tuple of ``(encoding, count)``. ``encoding`` is a list of byte
            values (or a ``bytes`` object when ``as_bytes=True``) containing
            the assembled machine code, or ``None`` on failure. ``count`` is
            the number of statements successfully assembled.
        """
        ...


def ks_version(major: int, minor: int) -> int: ...


def ks_arch_supported(arch: int) -> bool: ...


def version() -> tuple[int, int, int]: ...


def debug() -> str: ...


def strerror(errno: int) -> str: ...
