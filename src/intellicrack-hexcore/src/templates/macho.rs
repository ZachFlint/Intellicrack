use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(mach_header());
    registry.register(mach_header_be());
    registry.register(mach_header_64());
    registry.register(mach_header_64_be());
    registry.register(fat_header());
    registry.register(fat_arch());
    registry.register(load_command());
    registry.register(segment_command());
    registry.register(segment_command_64());
    registry.register(section());
    registry.register(section_64());
    registry.register(symtab_command());
    registry.register(dylib_command());
    registry.register(dyld_info_command());
    registry.register(main_command());
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

fn mach_header_common_fields() -> Vec<FieldDefinition> {
    vec![
        fd(
            "magic",
            FieldType::UInt32,
            "Mach-O magic (0xFEEDFACE / 0xCEFAEDFE)",
        ),
        fd("cputype", FieldType::Int32, "CPU type identifier"),
        fd("cpusubtype", FieldType::Int32, "CPU subtype identifier"),
        fd(
            "filetype",
            FieldType::UInt32,
            "Type of file (MH_EXECUTE=2, MH_DYLIB=6, etc.)",
        ),
        fd("ncmds", FieldType::UInt32, "Number of load commands"),
        fd(
            "sizeofcmds",
            FieldType::UInt32,
            "Size of all load commands in bytes",
        ),
        fd(
            "flags",
            FieldType::UInt32,
            "Flags (MH_NOUNDEFS, MH_PIE, etc.)",
        ),
    ]
}

fn mach_header() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER".to_string(),
        description: "Mach-O 32-bit header little-endian (28 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xCE, 0xFA, 0xED, 0xFE],
        }),
        fields: mach_header_common_fields(),
    }
}

fn mach_header_be() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER_BE".to_string(),
        description: "Mach-O 32-bit header big-endian (28 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Big,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xFE, 0xED, 0xFA, 0xCE],
        }),
        fields: mach_header_common_fields(),
    }
}

fn mach_header_64_common_fields() -> Vec<FieldDefinition> {
    vec![
        fd(
            "magic",
            FieldType::UInt32,
            "Mach-O 64-bit magic (0xFEEDFACF / 0xCFFAEDFE)",
        ),
        fd("cputype", FieldType::Int32, "CPU type identifier"),
        fd("cpusubtype", FieldType::Int32, "CPU subtype identifier"),
        fd("filetype", FieldType::UInt32, "Type of file"),
        fd("ncmds", FieldType::UInt32, "Number of load commands"),
        fd(
            "sizeofcmds",
            FieldType::UInt32,
            "Size of all load commands in bytes",
        ),
        fd("flags", FieldType::UInt32, "Flags"),
        fd("reserved", FieldType::UInt32, "Reserved (64-bit padding)"),
    ]
}

fn mach_header_64() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER_64".to_string(),
        description: "Mach-O 64-bit header little-endian (32 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xCF, 0xFA, 0xED, 0xFE],
        }),
        fields: mach_header_64_common_fields(),
    }
}

fn mach_header_64_be() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER_64_BE".to_string(),
        description: "Mach-O 64-bit header big-endian (32 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Big,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xFE, 0xED, 0xFA, 0xCF],
        }),
        fields: mach_header_64_common_fields(),
    }
}

fn fat_header() -> StructTemplate {
    StructTemplate {
        name: "FAT_HEADER".to_string(),
        description: "Mach-O fat/universal binary header (8 bytes, big-endian)".to_string(),
        default_endianness: Endianness::Big,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
        }),
        fields: vec![
            fd(
                "magic",
                FieldType::UInt32,
                "Fat magic (0xCAFEBABE or 0xBEBAFECA swapped)",
            ),
            fd(
                "nfat_arch",
                FieldType::UInt32,
                "Number of fat_arch entries following the header",
            ),
        ],
    }
}

fn fat_arch() -> StructTemplate {
    StructTemplate {
        name: "FAT_ARCH".to_string(),
        description: "Mach-O fat architecture descriptor (20 bytes, big-endian)".to_string(),
        default_endianness: Endianness::Big,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cputype", FieldType::UInt32, "CPU type for this slice"),
            fd(
                "cpusubtype",
                FieldType::UInt32,
                "CPU subtype for this slice",
            ),
            fd(
                "offset",
                FieldType::UInt32,
                "File offset to the start of this slice",
            ),
            fd("size", FieldType::UInt32, "Size of this slice in bytes"),
            fd(
                "align",
                FieldType::UInt32,
                "Alignment as a power of 2 for this slice",
            ),
        ],
    }
}

fn load_command() -> StructTemplate {
    StructTemplate {
        name: "LOAD_COMMAND".to_string(),
        description: "Mach-O load command header (8 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "cmd",
                FieldType::UInt32,
                "Load command type (LC_SEGMENT=0x1, LC_SEGMENT_64=0x19, etc.)",
            ),
            fd(
                "cmdsize",
                FieldType::UInt32,
                "Total size of command including data",
            ),
        ],
    }
}

fn segment_command() -> StructTemplate {
    StructTemplate {
        name: "SEGMENT_COMMAND".to_string(),
        description: "Mach-O 32-bit segment command LC_SEGMENT (56 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cmd", FieldType::UInt32, "LC_SEGMENT (0x1)"),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd(
                "segname",
                FieldType::FixedString(16),
                "Segment name (__TEXT, __DATA, etc.)",
            ),
            fd("vmaddr", FieldType::UInt32, "Virtual memory address"),
            fd("vmsize", FieldType::UInt32, "Virtual memory size"),
            fd("fileoff", FieldType::UInt32, "File offset of this segment"),
            fd("filesize", FieldType::UInt32, "File size of this segment"),
            fd("maxprot", FieldType::Int32, "Maximum VM protection"),
            fd("initprot", FieldType::Int32, "Initial VM protection"),
            fd(
                "nsects",
                FieldType::UInt32,
                "Number of sections in this segment",
            ),
            fd("flags", FieldType::UInt32, "Segment flags"),
        ],
    }
}

fn segment_command_64() -> StructTemplate {
    StructTemplate {
        name: "SEGMENT_COMMAND_64".to_string(),
        description: "Mach-O 64-bit segment command LC_SEGMENT_64 (72 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cmd", FieldType::UInt32, "LC_SEGMENT_64 (0x19)"),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd(
                "segname",
                FieldType::FixedString(16),
                "Segment name (__TEXT, __DATA, etc.)",
            ),
            fd("vmaddr", FieldType::UInt64, "Virtual memory address"),
            fd("vmsize", FieldType::UInt64, "Virtual memory size"),
            fd("fileoff", FieldType::UInt64, "File offset of this segment"),
            fd("filesize", FieldType::UInt64, "File size of this segment"),
            fd("maxprot", FieldType::Int32, "Maximum VM protection"),
            fd("initprot", FieldType::Int32, "Initial VM protection"),
            fd(
                "nsects",
                FieldType::UInt32,
                "Number of sections in this segment",
            ),
            fd("flags", FieldType::UInt32, "Segment flags"),
        ],
    }
}

fn section() -> StructTemplate {
    StructTemplate {
        name: "SECTION".to_string(),
        description: "Mach-O 32-bit section descriptor (68 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "sectname",
                FieldType::FixedString(16),
                "Section name (__text, __data, etc.)",
            ),
            fd("segname", FieldType::FixedString(16), "Parent segment name"),
            fd("addr", FieldType::UInt32, "Virtual memory address"),
            fd("size", FieldType::UInt32, "Size in bytes"),
            fd("offset", FieldType::UInt32, "File offset of section data"),
            fd(
                "align",
                FieldType::UInt32,
                "Section alignment as a power of 2",
            ),
            fd(
                "reloff",
                FieldType::UInt32,
                "File offset of relocation entries",
            ),
            fd("nreloc", FieldType::UInt32, "Number of relocation entries"),
            fd("flags", FieldType::UInt32, "Section type and attributes"),
            fd(
                "reserved1",
                FieldType::UInt32,
                "Reserved (for offset or index)",
            ),
            fd(
                "reserved2",
                FieldType::UInt32,
                "Reserved (for count or sizeof)",
            ),
        ],
    }
}

fn section_64() -> StructTemplate {
    StructTemplate {
        name: "SECTION_64".to_string(),
        description: "Mach-O 64-bit section descriptor (80 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "sectname",
                FieldType::FixedString(16),
                "Section name (__text, __data, etc.)",
            ),
            fd("segname", FieldType::FixedString(16), "Parent segment name"),
            fd("addr", FieldType::UInt64, "Virtual memory address"),
            fd("size", FieldType::UInt64, "Size in bytes"),
            fd("offset", FieldType::UInt32, "File offset of section data"),
            fd(
                "align",
                FieldType::UInt32,
                "Section alignment as a power of 2",
            ),
            fd(
                "reloff",
                FieldType::UInt32,
                "File offset of relocation entries",
            ),
            fd("nreloc", FieldType::UInt32, "Number of relocation entries"),
            fd("flags", FieldType::UInt32, "Section type and attributes"),
            fd(
                "reserved1",
                FieldType::UInt32,
                "Reserved (for offset or index)",
            ),
            fd(
                "reserved2",
                FieldType::UInt32,
                "Reserved (for count or sizeof)",
            ),
            fd("reserved3", FieldType::UInt32, "Reserved"),
        ],
    }
}

fn symtab_command() -> StructTemplate {
    StructTemplate {
        name: "SYMTAB_COMMAND".to_string(),
        description: "Mach-O symbol table load command LC_SYMTAB (24 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cmd", FieldType::UInt32, "LC_SYMTAB (0x2)"),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd("symoff", FieldType::UInt32, "File offset of symbol table"),
            fd("nsyms", FieldType::UInt32, "Number of symbol table entries"),
            fd("stroff", FieldType::UInt32, "File offset of string table"),
            fd(
                "strsize",
                FieldType::UInt32,
                "Size of string table in bytes",
            ),
        ],
    }
}

fn dylib_command() -> StructTemplate {
    StructTemplate {
        name: "DYLIB_COMMAND".to_string(),
        description: "Mach-O dynamic library load command LC_LOAD_DYLIB (0xC) / LC_ID_DYLIB (0xD)"
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "cmd",
                FieldType::UInt32,
                "LC_LOAD_DYLIB (0xC) or LC_ID_DYLIB (0xD)",
            ),
            fd(
                "cmdsize",
                FieldType::UInt32,
                "Size of this command including name string",
            ),
            fd(
                "name_offset",
                FieldType::UInt32,
                "Offset to library name string from start of this command",
            ),
            fd(
                "timestamp",
                FieldType::UInt32,
                "Library build timestamp (seconds since epoch)",
            ),
            fd(
                "current_version",
                FieldType::UInt32,
                "Current library version (packed 32-bit)",
            ),
            fd(
                "compatibility_version",
                FieldType::UInt32,
                "Compatibility library version (packed 32-bit)",
            ),
            fd(
                "name",
                FieldType::FixedString(1),
                "Null-terminated library name string at name_offset (variable length)",
            ),
        ],
    }
}

fn dyld_info_command() -> StructTemplate {
    StructTemplate {
        name: "DYLD_INFO_COMMAND".to_string(),
        description: "Mach-O dyld info-only load command LC_DYLD_INFO_ONLY (0x80000022, 48 bytes)"
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "cmd",
                FieldType::UInt32,
                "LC_DYLD_INFO_ONLY (0x80000022) or LC_DYLD_INFO (0x22)",
            ),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd(
                "rebase_off",
                FieldType::UInt32,
                "File offset of rebase info",
            ),
            fd(
                "rebase_size",
                FieldType::UInt32,
                "Size of rebase info in bytes",
            ),
            fd("bind_off", FieldType::UInt32, "File offset of binding info"),
            fd(
                "bind_size",
                FieldType::UInt32,
                "Size of binding info in bytes",
            ),
            fd(
                "weak_bind_off",
                FieldType::UInt32,
                "File offset of weak binding info",
            ),
            fd(
                "weak_bind_size",
                FieldType::UInt32,
                "Size of weak binding info in bytes",
            ),
            fd(
                "lazy_bind_off",
                FieldType::UInt32,
                "File offset of lazy binding info",
            ),
            fd(
                "lazy_bind_size",
                FieldType::UInt32,
                "Size of lazy binding info in bytes",
            ),
            fd(
                "export_off",
                FieldType::UInt32,
                "File offset of exported symbols trie",
            ),
            fd(
                "export_size",
                FieldType::UInt32,
                "Size of exported symbols trie in bytes",
            ),
        ],
    }
}

fn main_command() -> StructTemplate {
    StructTemplate {
        name: "MAIN_COMMAND".to_string(),
        description: "Mach-O program entry point load command LC_MAIN (0x80000028, 24 bytes)"
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cmd", FieldType::UInt32, "LC_MAIN (0x80000028)"),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd(
                "entryoff",
                FieldType::UInt64,
                "File offset of main() entry point",
            ),
            fd(
                "stacksize",
                FieldType::UInt64,
                "Initial stack size (0 means default)",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::TemplateRegistry;

    #[test]
    fn test_mach_header_registered() {
        let reg = TemplateRegistry::new();
        let list = reg.list();
        assert!(list.iter().any(|(name, _)| name == "MACH_HEADER"));
        assert!(list.iter().any(|(name, _)| name == "MACH_HEADER_BE"));
        assert!(list.iter().any(|(name, _)| name == "MACH_HEADER_64"));
        assert!(list.iter().any(|(name, _)| name == "MACH_HEADER_64_BE"));
        assert!(list.iter().any(|(name, _)| name == "FAT_HEADER"));
        assert!(list.iter().any(|(name, _)| name == "FAT_ARCH"));
        assert!(list.iter().any(|(name, _)| name == "LOAD_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "SEGMENT_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "SEGMENT_COMMAND_64"));
        assert!(list.iter().any(|(name, _)| name == "SECTION"));
        assert!(list.iter().any(|(name, _)| name == "SECTION_64"));
        assert!(list.iter().any(|(name, _)| name == "SYMTAB_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "DYLIB_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "DYLD_INFO_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "MAIN_COMMAND"));
    }

    #[test]
    fn test_apply_mach_header_64() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 64];
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        data[16] = 0x05;
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;

        let fields = reg.apply("MACH_HEADER_64", &data, 0).unwrap();
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0].name, "magic");
        assert_eq!(fields[4].name, "ncmds");
    }

    #[test]
    fn test_apply_mach_header_be() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 32];
        data[0] = 0xFE;
        data[1] = 0xED;
        data[2] = 0xFA;
        data[3] = 0xCE;

        let fields = reg.apply("MACH_HEADER_BE", &data, 0).unwrap();
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[0].name, "magic");
        assert!(fields[0].display_value.contains("FEEDFACE"));
    }

    #[test]
    fn test_apply_mach_header_64_be() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 32];
        data[0] = 0xFE;
        data[1] = 0xED;
        data[2] = 0xFA;
        data[3] = 0xCF;

        let fields = reg.apply("MACH_HEADER_64_BE", &data, 0).unwrap();
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0].name, "magic");
        assert!(fields[0].display_value.contains("FEEDFACF"));
    }

    #[test]
    fn test_apply_fat_header_and_arches() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 8 + 20 * 2];

        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE;
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x02;

        let arch0_offset: usize = 8;
        data[arch0_offset..arch0_offset + 4].copy_from_slice(&0x0000_0007u32.to_be_bytes());
        data[arch0_offset + 4..arch0_offset + 8].copy_from_slice(&0x0000_0003u32.to_be_bytes());
        data[arch0_offset + 8..arch0_offset + 12].copy_from_slice(&0x0000_1000u32.to_be_bytes());
        data[arch0_offset + 12..arch0_offset + 16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        data[arch0_offset + 16..arch0_offset + 20].copy_from_slice(&0x0000_000Cu32.to_be_bytes());

        let arch1_offset: usize = 28;
        data[arch1_offset..arch1_offset + 4].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        data[arch1_offset + 4..arch1_offset + 8].copy_from_slice(&0x0000_0003u32.to_be_bytes());
        data[arch1_offset + 8..arch1_offset + 12].copy_from_slice(&0x0001_1000u32.to_be_bytes());
        data[arch1_offset + 12..arch1_offset + 16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        data[arch1_offset + 16..arch1_offset + 20].copy_from_slice(&0x0000_000Eu32.to_be_bytes());

        let fat = reg.apply("FAT_HEADER", &data, 0).unwrap();
        assert_eq!(fat.len(), 2);
        assert_eq!(fat[0].name, "magic");
        assert!(fat[0].display_value.contains("CAFEBABE"));
        assert_eq!(fat[1].name, "nfat_arch");
        assert!(fat[1].display_value.contains('2'));

        let arch0 = reg.apply("FAT_ARCH", &data, arch0_offset).unwrap();
        assert_eq!(arch0.len(), 5);
        assert_eq!(arch0[0].name, "cputype");
        assert!(arch0[0].display_value.contains('7'));
        assert_eq!(arch0[2].name, "offset");
        assert!(arch0[2].display_value.contains("00001000"));

        let arch1 = reg.apply("FAT_ARCH", &data, arch1_offset).unwrap();
        assert_eq!(arch1.len(), 5);
        assert_eq!(arch1[0].name, "cputype");
        assert!(arch1[0].display_value.contains("01000007"));
        assert_eq!(arch1[4].name, "align");
        assert!(arch1[4].display_value.contains("0000000E"));
    }

    #[test]
    fn test_apply_segment_command_and_section() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 56 + 68];

        data[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        data[4..8].copy_from_slice(&((56u32 + 68u32).to_le_bytes()));
        let segname: &[u8] = b"__TEXT";
        data[8..8 + segname.len()].copy_from_slice(segname);
        data[24..28].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        data[32..36].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        data[36..40].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        data[40..44].copy_from_slice(&0x0000_0007i32.to_le_bytes());
        data[44..48].copy_from_slice(&0x0000_0005i32.to_le_bytes());
        data[48..52].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        data[52..56].copy_from_slice(&0x0000_0000u32.to_le_bytes());

        let seg = reg.apply("SEGMENT_COMMAND", &data, 0).unwrap();
        assert_eq!(seg.len(), 11);
        assert_eq!(seg[0].name, "cmd");
        assert!(seg[0].display_value.contains("00000001"));
        assert_eq!(seg[2].name, "segname");
        assert!(seg[2].display_value.contains("__TEXT"));
        assert_eq!(seg[9].name, "nsects");
        assert!(seg[9].display_value.contains('1'));

        let sect_off: usize = 56;
        let sectname: &[u8] = b"__text";
        data[sect_off..sect_off + sectname.len()].copy_from_slice(sectname);
        let segname2: &[u8] = b"__TEXT";
        data[sect_off + 16..sect_off + 16 + segname2.len()].copy_from_slice(segname2);
        data[sect_off + 32..sect_off + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        data[sect_off + 36..sect_off + 40].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        data[sect_off + 40..sect_off + 44].copy_from_slice(&0x0000_0080u32.to_le_bytes());
        data[sect_off + 44..sect_off + 48].copy_from_slice(&0x0000_0004u32.to_le_bytes());
        data[sect_off + 48..sect_off + 52].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        data[sect_off + 52..sect_off + 56].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        data[sect_off + 56..sect_off + 60].copy_from_slice(&0x8000_0400u32.to_le_bytes());
        data[sect_off + 60..sect_off + 64].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        data[sect_off + 64..sect_off + 68].copy_from_slice(&0x0000_0000u32.to_le_bytes());

        let sect = reg.apply("SECTION", &data, sect_off).unwrap();
        assert_eq!(sect.len(), 11);
        assert_eq!(sect[0].name, "sectname");
        assert!(sect[0].display_value.contains("__text"));
        assert_eq!(sect[1].name, "segname");
        assert!(sect[1].display_value.contains("__TEXT"));
        assert_eq!(sect[2].name, "addr");
        assert!(sect[2].display_value.contains("00001000"));
        assert_eq!(sect[8].name, "flags");
        assert!(sect[8].display_value.contains("80000400"));
    }

    #[test]
    fn test_apply_symtab_command() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0x0000_0002u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x0000_0018u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x0000_4000u32.to_le_bytes());
        data[12..16].copy_from_slice(&0x0000_0020u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x0000_5000u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x0000_0200u32.to_le_bytes());

        let fields = reg.apply("SYMTAB_COMMAND", &data, 0).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, "cmd");
        assert!(fields[0].display_value.contains("00000002"));
        assert_eq!(fields[2].name, "symoff");
        assert!(fields[2].display_value.contains("00004000"));
        assert_eq!(fields[3].name, "nsyms");
        assert!(fields[3].display_value.contains("00000020"));
        assert_eq!(fields[4].name, "stroff");
        assert!(fields[4].display_value.contains("00005000"));
        assert_eq!(fields[5].name, "strsize");
        assert!(fields[5].display_value.contains("00000200"));
    }

    #[test]
    fn test_apply_main_command() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0x8000_0028u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x0000_0018u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x0000_0000_0001_0000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x0000_0000_0010_0000u64.to_le_bytes());

        let fields = reg.apply("MAIN_COMMAND", &data, 0).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "cmd");
        assert!(fields[0].display_value.contains("80000028"));
        assert_eq!(fields[1].name, "cmdsize");
        assert!(fields[1].display_value.contains("00000018"));
        assert_eq!(fields[2].name, "entryoff");
        assert!(fields[2].display_value.contains("0000000000010000"));
        assert_eq!(fields[3].name, "stacksize");
        assert!(fields[3].display_value.contains("0000000000100000"));
    }
}
