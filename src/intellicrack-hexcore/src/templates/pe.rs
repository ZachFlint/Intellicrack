use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(image_dos_header());
    registry.register(image_file_header());
    registry.register(image_optional_header32());
    registry.register(image_optional_header64());
    registry.register(image_section_header());
    registry.register(image_data_directory());
    registry.register(image_import_descriptor());
    registry.register(image_export_directory());
}

fn image_dos_header() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_DOS_HEADER".to_string(),
        description: "PE DOS Header (64 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x4D, 0x5A],
        }),
        fields: vec![
            fd("e_magic", FieldType::UInt16, "Magic number (0x5A4D = 'MZ')"),
            fd("e_cblp", FieldType::UInt16, "Bytes on last page of file"),
            fd("e_cp", FieldType::UInt16, "Pages in file"),
            fd("e_crlc", FieldType::UInt16, "Relocations"),
            fd(
                "e_cparhdr",
                FieldType::UInt16,
                "Size of header in paragraphs",
            ),
            fd(
                "e_minalloc",
                FieldType::UInt16,
                "Minimum extra paragraphs needed",
            ),
            fd(
                "e_maxalloc",
                FieldType::UInt16,
                "Maximum extra paragraphs needed",
            ),
            fd("e_ss", FieldType::UInt16, "Initial (relative) SS value"),
            fd("e_sp", FieldType::UInt16, "Initial SP value"),
            fd("e_csum", FieldType::UInt16, "Checksum"),
            fd("e_ip", FieldType::UInt16, "Initial IP value"),
            fd("e_cs", FieldType::UInt16, "Initial (relative) CS value"),
            fd(
                "e_lfarlc",
                FieldType::UInt16,
                "File address of relocation table",
            ),
            fd("e_ovno", FieldType::UInt16, "Overlay number"),
            fd(
                "e_res",
                FieldType::Array {
                    element_type: Box::new(FieldType::UInt16),
                    count: 4,
                },
                "Reserved words",
            ),
            fd("e_oemid", FieldType::UInt16, "OEM identifier"),
            fd("e_oeminfo", FieldType::UInt16, "OEM information"),
            fd(
                "e_res2",
                FieldType::Array {
                    element_type: Box::new(FieldType::UInt16),
                    count: 10,
                },
                "Reserved words",
            ),
            fd(
                "e_lfanew",
                FieldType::Int32,
                "File address of new exe header",
            ),
        ],
    }
}

fn image_file_header() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_FILE_HEADER".to_string(),
        description: "PE COFF File Header (20 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields: vec![
            fd("Machine", FieldType::UInt16, "Target machine type"),
            fd("NumberOfSections", FieldType::UInt16, "Number of sections"),
            fd(
                "TimeDateStamp",
                FieldType::UInt32,
                "UNIX timestamp of creation",
            ),
            fd(
                "PointerToSymbolTable",
                FieldType::UInt32,
                "File offset of COFF symbol table",
            ),
            fd(
                "NumberOfSymbols",
                FieldType::UInt32,
                "Number of entries in symbol table",
            ),
            fd(
                "SizeOfOptionalHeader",
                FieldType::UInt16,
                "Size of optional header",
            ),
            fd(
                "Characteristics",
                FieldType::UInt16,
                "Flags indicating file attributes",
            ),
        ],
    }
}

fn optional_header_common_fields() -> Vec<FieldDefinition> {
    vec![
        fd(
            "MajorLinkerVersion",
            FieldType::UInt8,
            "Linker major version",
        ),
        fd(
            "MinorLinkerVersion",
            FieldType::UInt8,
            "Linker minor version",
        ),
        fd("SizeOfCode", FieldType::UInt32, "Size of code sections"),
        fd(
            "SizeOfInitializedData",
            FieldType::UInt32,
            "Size of initialized data",
        ),
        fd("SizeOfUninitializedData", FieldType::UInt32, "Size of BSS"),
        fd("AddressOfEntryPoint", FieldType::UInt32, "Entry point RVA"),
        fd("BaseOfCode", FieldType::UInt32, "Base of code section RVA"),
    ]
}

fn optional_header_tail_fields(stack_type: FieldType) -> Vec<FieldDefinition> {
    vec![
        fd(
            "SectionAlignment",
            FieldType::UInt32,
            "Section alignment in memory",
        ),
        fd(
            "FileAlignment",
            FieldType::UInt32,
            "Section alignment on disk",
        ),
        fd(
            "MajorOperatingSystemVersion",
            FieldType::UInt16,
            "Required OS major version",
        ),
        fd(
            "MinorOperatingSystemVersion",
            FieldType::UInt16,
            "Required OS minor version",
        ),
        fd(
            "MajorImageVersion",
            FieldType::UInt16,
            "Image major version",
        ),
        fd(
            "MinorImageVersion",
            FieldType::UInt16,
            "Image minor version",
        ),
        fd(
            "MajorSubsystemVersion",
            FieldType::UInt16,
            "Subsystem major version",
        ),
        fd(
            "MinorSubsystemVersion",
            FieldType::UInt16,
            "Subsystem minor version",
        ),
        fd(
            "Win32VersionValue",
            FieldType::UInt32,
            "Reserved, must be zero",
        ),
        fd("SizeOfImage", FieldType::UInt32, "Size of image in memory"),
        fd(
            "SizeOfHeaders",
            FieldType::UInt32,
            "Combined size of all headers",
        ),
        fd("CheckSum", FieldType::UInt32, "Image file checksum"),
        fd("Subsystem", FieldType::UInt16, "Required subsystem"),
        fd(
            "DllCharacteristics",
            FieldType::UInt16,
            "DLL characteristics flags",
        ),
        fd(
            "SizeOfStackReserve",
            stack_type.clone(),
            "Stack reserve size",
        ),
        fd("SizeOfStackCommit", stack_type.clone(), "Stack commit size"),
        fd("SizeOfHeapReserve", stack_type.clone(), "Heap reserve size"),
        fd("SizeOfHeapCommit", stack_type, "Heap commit size"),
        fd("LoaderFlags", FieldType::UInt32, "Reserved, must be zero"),
        fd(
            "NumberOfRvaAndSizes",
            FieldType::UInt32,
            "Number of data directory entries",
        ),
    ]
}

fn image_data_directory_fields() -> Vec<FieldDefinition> {
    vec![
        fd(
            "ExportTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Export Table (.edata) - IMAGE_DIRECTORY_ENTRY_EXPORT",
        ),
        fd(
            "ImportTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Import Table (.idata) - IMAGE_DIRECTORY_ENTRY_IMPORT",
        ),
        fd(
            "ResourceTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Resource Table (.rsrc) - IMAGE_DIRECTORY_ENTRY_RESOURCE",
        ),
        fd(
            "ExceptionTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Exception Table (.pdata) - IMAGE_DIRECTORY_ENTRY_EXCEPTION",
        ),
        fd(
            "CertificateTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Attribute Certificate Table - IMAGE_DIRECTORY_ENTRY_SECURITY",
        ),
        fd(
            "BaseRelocationTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Base Relocation Table (.reloc) - IMAGE_DIRECTORY_ENTRY_BASERELOC",
        ),
        fd(
            "Debug",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Debug Data - IMAGE_DIRECTORY_ENTRY_DEBUG",
        ),
        fd(
            "Architecture",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Reserved, must be 0 - IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
        ),
        fd(
            "GlobalPtr",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "RVA of the value to be stored in the global pointer register - IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
        ),
        fd(
            "TLSTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Thread Local Storage Table - IMAGE_DIRECTORY_ENTRY_TLS",
        ),
        fd(
            "LoadConfigTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Load Configuration Table - IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
        ),
        fd(
            "BoundImportTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Bound Import Table - IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
        ),
        fd(
            "ImportAddressTable",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Import Address Table - IMAGE_DIRECTORY_ENTRY_IAT",
        ),
        fd(
            "DelayImportDescriptor",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Delay Import Descriptor - IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
        ),
        fd(
            "CLRRuntimeHeader",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "CLR Runtime Header (.cormeta) - IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
        ),
        fd(
            "Reserved",
            FieldType::StructRef("IMAGE_DATA_DIRECTORY".to_string()),
            "Reserved, must be 0",
        ),
    ]
}

fn image_optional_header32() -> StructTemplate {
    let mut fields = vec![fd(
        "Magic",
        FieldType::UInt16,
        "Magic number (0x10B = PE32)",
    )];
    fields.extend(optional_header_common_fields());
    fields.push(fd(
        "BaseOfData",
        FieldType::UInt32,
        "Base of data section RVA",
    ));
    fields.push(fd(
        "ImageBase",
        FieldType::UInt32,
        "Preferred image base address",
    ));
    fields.extend(optional_header_tail_fields(FieldType::UInt32));
    fields.extend(image_data_directory_fields());

    StructTemplate {
        name: "IMAGE_OPTIONAL_HEADER32".to_string(),
        description: "PE32 Optional Header (96 bytes standard + data directories)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields,
    }
}

fn image_optional_header64() -> StructTemplate {
    let mut fields = vec![fd(
        "Magic",
        FieldType::UInt16,
        "Magic number (0x20B = PE32+)",
    )];
    fields.extend(optional_header_common_fields());
    fields.push(fd(
        "ImageBase",
        FieldType::UInt64,
        "Preferred image base address",
    ));
    fields.extend(optional_header_tail_fields(FieldType::UInt64));
    fields.extend(image_data_directory_fields());

    StructTemplate {
        name: "IMAGE_OPTIONAL_HEADER64".to_string(),
        description: "PE32+ Optional Header (112 bytes standard + data directories)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields,
    }
}

fn image_section_header() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_SECTION_HEADER".to_string(),
        description: "PE Section Header (40 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "Name",
                FieldType::FixedString(8),
                "Section name (8 bytes, null-padded)",
            ),
            fd(
                "VirtualSize",
                FieldType::UInt32,
                "Size in memory (or PhysicalAddress)",
            ),
            fd("VirtualAddress", FieldType::UInt32, "RVA of section"),
            fd(
                "SizeOfRawData",
                FieldType::UInt32,
                "Size of section on disk",
            ),
            fd(
                "PointerToRawData",
                FieldType::UInt32,
                "File offset of section",
            ),
            fd(
                "PointerToRelocations",
                FieldType::UInt32,
                "File offset of relocations",
            ),
            fd(
                "PointerToLinenumbers",
                FieldType::UInt32,
                "File offset of line numbers",
            ),
            fd(
                "NumberOfRelocations",
                FieldType::UInt16,
                "Number of relocations",
            ),
            fd(
                "NumberOfLinenumbers",
                FieldType::UInt16,
                "Number of line numbers",
            ),
            fd("Characteristics", FieldType::UInt32, "Section flags"),
        ],
    }
}

fn image_data_directory() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_DATA_DIRECTORY".to_string(),
        description: "PE Data Directory Entry (8 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields: vec![
            fd("VirtualAddress", FieldType::UInt32, "RVA of the data"),
            fd("Size", FieldType::UInt32, "Size of the data"),
        ],
    }
}

fn image_import_descriptor() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_IMPORT_DESCRIPTOR".to_string(),
        description: "PE Import Directory Entry (20 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "OriginalFirstThunk",
                FieldType::UInt32,
                "RVA of Import Lookup Table (ILT)",
            ),
            fd(
                "TimeDateStamp",
                FieldType::UInt32,
                "Timestamp (0 if not bound)",
            ),
            fd(
                "ForwarderChain",
                FieldType::UInt32,
                "Index of first forwarder ref",
            ),
            fd("Name", FieldType::UInt32, "RVA of DLL name string"),
            fd(
                "FirstThunk",
                FieldType::UInt32,
                "RVA of Import Address Table (IAT)",
            ),
        ],
    }
}

fn image_export_directory() -> StructTemplate {
    StructTemplate {
        name: "IMAGE_EXPORT_DIRECTORY".to_string(),
        description: "PE Export Directory Table (40 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("PE".to_string()),
        magic_detection: None,
        fields: vec![
            fd("Characteristics", FieldType::UInt32, "Reserved, must be 0"),
            fd(
                "TimeDateStamp",
                FieldType::UInt32,
                "Export creation timestamp",
            ),
            fd("MajorVersion", FieldType::UInt16, "Major version number"),
            fd("MinorVersion", FieldType::UInt16, "Minor version number"),
            fd("Name", FieldType::UInt32, "RVA of DLL name"),
            fd("Base", FieldType::UInt32, "Starting ordinal number"),
            fd(
                "NumberOfFunctions",
                FieldType::UInt32,
                "Number of entries in EAT",
            ),
            fd(
                "NumberOfNames",
                FieldType::UInt32,
                "Number of entries in name pointer table",
            ),
            fd(
                "AddressOfFunctions",
                FieldType::UInt32,
                "RVA of Export Address Table",
            ),
            fd(
                "AddressOfNames",
                FieldType::UInt32,
                "RVA of Export Name Pointer Table",
            ),
            fd(
                "AddressOfNameOrdinals",
                FieldType::UInt32,
                "RVA of Ordinal Table",
            ),
        ],
    }
}

fn fd(name: &str, field_type: FieldType, description: &str) -> FieldDefinition {
    FieldDefinition {
        name: name.to_string(),
        field_type,
        endianness: None,
        description: description.to_string(),
        color: None,
        validation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::TemplateRegistry;

    const DATA_DIR_NAMES: [&str; 16] = [
        "ExportTable",
        "ImportTable",
        "ResourceTable",
        "ExceptionTable",
        "CertificateTable",
        "BaseRelocationTable",
        "Debug",
        "Architecture",
        "GlobalPtr",
        "TLSTable",
        "LoadConfigTable",
        "BoundImportTable",
        "ImportAddressTable",
        "DelayImportDescriptor",
        "CLRRuntimeHeader",
        "Reserved",
    ];

    /// Gate for finding #27: `IMAGE_OPTIONAL_HEADER32` must expose the full
    /// 16-entry `DataDirectory` array (128 bytes) after `NumberOfRvaAndSizes`,
    /// wired to the existing `IMAGE_DATA_DIRECTORY` template via `StructRef`.
    ///
    /// Mutation caught: removing `fields.extend(image_data_directory_fields())`
    /// from `image_optional_header32()` makes `.find(|f| f.name == "ExportTable")`
    /// return `None` (panicking the `.expect`), and the byte total falls from
    /// 224 to 96.
    #[test]
    fn test_image_optional_header32_includes_data_directories() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 224];
        data[0] = 0x0B;
        data[1] = 0x01; // Magic = 0x10B (PE32)

        // ExportTable (index 0) at offset 96: VirtualAddress=0x1000, Size=0x50
        data[96..100].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        data[100..104].copy_from_slice(&0x0000_0050u32.to_le_bytes());

        let fields = reg.apply("IMAGE_OPTIONAL_HEADER32", &data, 0).unwrap();

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(
            total_size, 224,
            "IMAGE_OPTIONAL_HEADER32 must consume the full 96-byte standard header \
             plus the 128-byte DataDirectory array"
        );

        for (i, name) in DATA_DIR_NAMES.into_iter().enumerate() {
            let entry = fields
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("data directory entry '{name}' must be present"));
            assert_eq!(entry.offset, 96 + i * 8);
            assert_eq!(entry.size, 8);
            assert_eq!(entry.children.len(), 2);
            assert_eq!(entry.children[0].name, "VirtualAddress");
            assert_eq!(entry.children[1].name, "Size");
        }

        let export = fields.iter().find(|f| f.name == "ExportTable").unwrap();
        // Independent oracle: u32::from_le_bytes([0x00,0x10,0x00,0x00]) = 4096
        assert!(export.children[0].display_value.contains("4096"));
        // Independent oracle: u32::from_le_bytes([0x50,0x00,0x00,0x00]) = 80
        assert!(export.children[1].display_value.contains("80"));
    }

    /// Gate for finding #27: `IMAGE_OPTIONAL_HEADER64` must expose the same
    /// 16-entry `DataDirectory` array, starting after the 112-byte PE32+
    /// standard fields.
    #[test]
    fn test_image_optional_header64_includes_data_directories() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 240];
        data[0] = 0x0B;
        data[1] = 0x02; // Magic = 0x20B (PE32+)

        // ExportTable (index 0) at offset 112: VirtualAddress=0x2000, Size=0x60
        data[112..116].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        data[116..120].copy_from_slice(&0x0000_0060u32.to_le_bytes());

        let fields = reg.apply("IMAGE_OPTIONAL_HEADER64", &data, 0).unwrap();

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(
            total_size, 240,
            "IMAGE_OPTIONAL_HEADER64 must consume the full 112-byte standard header \
             plus the 128-byte DataDirectory array"
        );

        for (i, name) in DATA_DIR_NAMES.into_iter().enumerate() {
            let entry = fields
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("data directory entry '{name}' must be present"));
            assert_eq!(entry.offset, 112 + i * 8);
            assert_eq!(entry.size, 8);
        }

        let export = fields.iter().find(|f| f.name == "ExportTable").unwrap();
        // Independent oracle: u32::from_le_bytes([0x00,0x20,0x00,0x00]) = 8192
        assert!(export.children[0].display_value.contains("8192"));
        // Independent oracle: u32::from_le_bytes([0x60,0x00,0x00,0x00]) = 96
        assert!(export.children[1].display_value.contains("96"));
    }
}
