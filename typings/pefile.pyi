class Structure:
    def __init__(self, *args: object, **kwargs: object) -> None: ...
    def get_file_offset(self) -> int: ...
    def sizeof(self) -> int: ...
    def dump(self, indentation: int = 0) -> list[str]: ...
    def dump_dict(self) -> dict[str, object]: ...

class SectionStructure(Structure):
    Name: bytes
    Misc: int
    Misc_PhysicalAddress: int
    Misc_VirtualSize: int
    VirtualAddress: int
    SizeOfRawData: int
    PointerToRawData: int
    PointerToRelocations: int
    PointerToLinenumbers: int
    NumberOfRelocations: int
    NumberOfLinenumbers: int
    Characteristics: int
    pe: PE
    def get_entropy(self) -> float: ...
    def get_data(self, start: int | None = None, length: int | None = None) -> bytes: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def contains_offset(self, offset: int) -> bool: ...
    def contains_rva(self, rva: int) -> bool: ...
    def contains(self, rva: int) -> bool: ...
    def get_PointerToRawData_adj(self) -> int: ...
    def get_VirtualAddress_adj(self) -> int: ...
    def get_hash_sha1(self) -> str | None: ...
    def get_hash_sha256(self) -> str | None: ...
    def get_hash_sha512(self) -> str | None: ...
    def get_hash_md5(self) -> str | None: ...

class DataContainer:
    def __init__(self, **kwargs: object) -> None: ...

class ImportDescData(DataContainer):
    dll: bytes
    imports: list[ImportData]
    struct: Structure

class ImportData(DataContainer):
    ordinal: int
    name: bytes | None
    bound: int
    address: int
    hint: int
    import_by_ordinal: bool
    thunk_offset: int
    thunk_rva: int
    hint_name_table_rva: int | None

class ExportDirData(DataContainer):
    struct: Structure
    symbols: list[ExportData]

class ExportData(DataContainer):
    ordinal: int
    address: int
    name: bytes | None
    forwarder: bytes | None

class FileHeader(Structure):
    Machine: int
    NumberOfSections: int
    TimeDateStamp: int
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int

class OptionalHeader(Structure):
    Magic: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    SizeOfCode: int
    SizeOfInitializedData: int
    SizeOfUninitializedData: int
    AddressOfEntryPoint: int
    BaseOfCode: int
    ImageBase: int
    SectionAlignment: int
    FileAlignment: int
    MajorOperatingSystemVersion: int
    MinorOperatingSystemVersion: int
    MajorImageVersion: int
    MinorImageVersion: int
    MajorSubsystemVersion: int
    MinorSubsystemVersion: int
    SizeOfImage: int
    SizeOfHeaders: int
    CheckSum: int
    Subsystem: int
    DllCharacteristics: int
    SizeOfStackReserve: int
    SizeOfStackCommit: int
    SizeOfHeapReserve: int
    SizeOfHeapCommit: int
    NumberOfRvaAndSizes: int

class DosHeader(Structure):
    e_magic: int
    e_lfanew: int

class NtHeaders(Structure):
    Signature: int

class PE:
    DOS_HEADER: DosHeader
    NT_HEADERS: NtHeaders
    FILE_HEADER: FileHeader
    OPTIONAL_HEADER: OptionalHeader
    PE_TYPE: int | None
    sections: list[SectionStructure]
    DIRECTORY_ENTRY_IMPORT: list[ImportDescData]
    DIRECTORY_ENTRY_EXPORT: ExportDirData
    DIRECTORY_ENTRY_RESOURCE: DataContainer
    DIRECTORY_ENTRY_DEBUG: list[DataContainer]
    DIRECTORY_ENTRY_BASERELOC: list[DataContainer]
    DIRECTORY_ENTRY_TLS: DataContainer
    DIRECTORY_ENTRY_BOUND_IMPORT: list[DataContainer]

    def __init__(
        self,
        name: str | None = None,
        data: bytes | None = None,
        fast_load: bool | None = None,
        max_symbol_exports: int = 2**16,
        max_repeated_symbol: int = 120,
    ) -> None: ...
    def __enter__(self) -> PE: ...
    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: object | None,
    ) -> None: ...
    def close(self) -> None: ...
    def parse_data_directories(
        self,
        directories: list[int] | None = None,
        forwarded_exports_only: bool = False,
        import_dllnames_only: bool = False,
    ) -> None: ...
    def get_warnings(self) -> list[str]: ...
    def get_overlay_data_start_offset(self) -> int | None: ...
    def get_overlay(self) -> bytes | None: ...
    def trim(self) -> bytes: ...
    def write(self, filename: str | None = None) -> bytearray: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def get_section_by_rva(self, rva: int) -> SectionStructure | None: ...
    def get_section_by_offset(self, offset: int) -> SectionStructure | None: ...
    def get_string_at_rva(self, rva: int, max_length: int = ...) -> bytes | None: ...
    def get_string_from_data(self, offset: int, data: bytes) -> bytes | None: ...
    def get_data(self, rva: int = 0, length: int | None = None) -> bytes: ...
    def get_imphash(self) -> str: ...
    def generate_checksum(self) -> int: ...

class PEFormatError(Exception):
    value: str
    def __init__(self, value: str | None = None) -> None: ...

fast_load: bool
MAX_SYMBOL_EXPORT_COUNT: int
