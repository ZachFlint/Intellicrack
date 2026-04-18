use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(elf32_ehdr());
    registry.register(elf64_ehdr());
    registry.register(elf32_phdr());
    registry.register(elf64_phdr());
    registry.register(elf32_shdr());
    registry.register(elf64_shdr());
    registry.register(elf32_sym());
    registry.register(elf64_sym());
    registry.register(elf32_rel());
    registry.register(elf64_rel());
    registry.register(elf32_rela());
    registry.register(elf64_rela());
    registry.register(elf32_dyn());
    registry.register(elf64_dyn());
    registry.register(elf_note());
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

const EI_DATA_OFFSET: usize = 5;
const ELFDATA2MSB: u8 = 2;

fn elf_endianness_switch_field() -> FieldDefinition {
    fd(
        "__ei_data_endianness",
        FieldType::EndiannessSwitch {
            peek_offset: EI_DATA_OFFSET,
            big_value: ELFDATA2MSB,
        },
        "Endianness inferred from e_ident[EI_DATA]: 1=little (ELFDATA2LSB), 2=big (ELFDATA2MSB)",
    )
}

fn elf32_ehdr() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Ehdr".to_string(),
        description: "ELF32 File Header (52 bytes, endianness from e_ident[EI_DATA])".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x7F, 0x45, 0x4C, 0x46],
        }),
        fields: vec![
            fd(
                "e_ident",
                FieldType::Bytes(16),
                "ELF identification (magic, class, data, version, OS/ABI, padding)",
            ),
            elf_endianness_switch_field(),
            fd("e_type", FieldType::UInt16, "Object file type"),
            fd("e_machine", FieldType::UInt16, "Architecture"),
            fd("e_version", FieldType::UInt32, "Object file version"),
            fd("e_entry", FieldType::UInt32, "Entry point virtual address"),
            fd(
                "e_phoff",
                FieldType::UInt32,
                "Program header table file offset",
            ),
            fd(
                "e_shoff",
                FieldType::UInt32,
                "Section header table file offset",
            ),
            fd("e_flags", FieldType::UInt32, "Processor-specific flags"),
            fd("e_ehsize", FieldType::UInt16, "ELF header size"),
            fd(
                "e_phentsize",
                FieldType::UInt16,
                "Program header table entry size",
            ),
            fd(
                "e_phnum",
                FieldType::UInt16,
                "Program header table entry count",
            ),
            fd(
                "e_shentsize",
                FieldType::UInt16,
                "Section header table entry size",
            ),
            fd(
                "e_shnum",
                FieldType::UInt16,
                "Section header table entry count",
            ),
            fd(
                "e_shstrndx",
                FieldType::UInt16,
                "Section name string table index",
            ),
        ],
    }
}

fn elf64_ehdr() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Ehdr".to_string(),
        description: "ELF64 File Header (64 bytes, endianness from e_ident[EI_DATA])".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x7F, 0x45, 0x4C, 0x46],
        }),
        fields: vec![
            fd("e_ident", FieldType::Bytes(16), "ELF identification"),
            elf_endianness_switch_field(),
            fd("e_type", FieldType::UInt16, "Object file type"),
            fd("e_machine", FieldType::UInt16, "Architecture"),
            fd("e_version", FieldType::UInt32, "Object file version"),
            fd("e_entry", FieldType::UInt64, "Entry point virtual address"),
            fd(
                "e_phoff",
                FieldType::UInt64,
                "Program header table file offset",
            ),
            fd(
                "e_shoff",
                FieldType::UInt64,
                "Section header table file offset",
            ),
            fd("e_flags", FieldType::UInt32, "Processor-specific flags"),
            fd("e_ehsize", FieldType::UInt16, "ELF header size"),
            fd(
                "e_phentsize",
                FieldType::UInt16,
                "Program header table entry size",
            ),
            fd(
                "e_phnum",
                FieldType::UInt16,
                "Program header table entry count",
            ),
            fd(
                "e_shentsize",
                FieldType::UInt16,
                "Section header table entry size",
            ),
            fd(
                "e_shnum",
                FieldType::UInt16,
                "Section header table entry count",
            ),
            fd(
                "e_shstrndx",
                FieldType::UInt16,
                "Section name string table index",
            ),
        ],
    }
}

fn elf32_phdr() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Phdr".to_string(),
        description: "ELF32 Program Header (32 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("p_type", FieldType::UInt32, "Segment type"),
            fd("p_offset", FieldType::UInt32, "Segment file offset"),
            fd("p_vaddr", FieldType::UInt32, "Segment virtual address"),
            fd("p_paddr", FieldType::UInt32, "Segment physical address"),
            fd("p_filesz", FieldType::UInt32, "Segment size in file"),
            fd("p_memsz", FieldType::UInt32, "Segment size in memory"),
            fd("p_flags", FieldType::UInt32, "Segment flags"),
            fd("p_align", FieldType::UInt32, "Segment alignment"),
        ],
    }
}

fn elf64_phdr() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Phdr".to_string(),
        description: "ELF64 Program Header (56 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("p_type", FieldType::UInt32, "Segment type"),
            fd("p_flags", FieldType::UInt32, "Segment flags"),
            fd("p_offset", FieldType::UInt64, "Segment file offset"),
            fd("p_vaddr", FieldType::UInt64, "Segment virtual address"),
            fd("p_paddr", FieldType::UInt64, "Segment physical address"),
            fd("p_filesz", FieldType::UInt64, "Segment size in file"),
            fd("p_memsz", FieldType::UInt64, "Segment size in memory"),
            fd("p_align", FieldType::UInt64, "Segment alignment"),
        ],
    }
}

fn elf32_shdr() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Shdr".to_string(),
        description: "ELF32 Section Header (40 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "sh_name",
                FieldType::UInt32,
                "Section name (index into section name string table)",
            ),
            fd("sh_type", FieldType::UInt32, "Section type"),
            fd("sh_flags", FieldType::UInt32, "Section flags"),
            fd("sh_addr", FieldType::UInt32, "Section virtual address"),
            fd("sh_offset", FieldType::UInt32, "Section file offset"),
            fd("sh_size", FieldType::UInt32, "Section size"),
            fd("sh_link", FieldType::UInt32, "Link to another section"),
            fd("sh_info", FieldType::UInt32, "Additional section info"),
            fd("sh_addralign", FieldType::UInt32, "Section alignment"),
            fd(
                "sh_entsize",
                FieldType::UInt32,
                "Entry size if section holds table",
            ),
        ],
    }
}

fn elf64_shdr() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Shdr".to_string(),
        description: "ELF64 Section Header (64 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "sh_name",
                FieldType::UInt32,
                "Section name (index into section name string table)",
            ),
            fd("sh_type", FieldType::UInt32, "Section type"),
            fd("sh_flags", FieldType::UInt64, "Section flags"),
            fd("sh_addr", FieldType::UInt64, "Section virtual address"),
            fd("sh_offset", FieldType::UInt64, "Section file offset"),
            fd("sh_size", FieldType::UInt64, "Section size"),
            fd("sh_link", FieldType::UInt32, "Link to another section"),
            fd("sh_info", FieldType::UInt32, "Additional section info"),
            fd("sh_addralign", FieldType::UInt64, "Section alignment"),
            fd(
                "sh_entsize",
                FieldType::UInt64,
                "Entry size if section holds table",
            ),
        ],
    }
}

fn elf32_sym() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Sym".to_string(),
        description: "ELF32 Symbol Table Entry (16 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "st_name",
                FieldType::UInt32,
                "Symbol name (index into string table)",
            ),
            fd("st_value", FieldType::UInt32, "Symbol value"),
            fd("st_size", FieldType::UInt32, "Symbol size"),
            fd(
                "st_info",
                FieldType::UInt8,
                "Symbol type and binding (high 4 bits binding, low 4 bits type)",
            ),
            fd(
                "st_other",
                FieldType::UInt8,
                "Symbol visibility (low 2 bits)",
            ),
            fd(
                "st_shndx",
                FieldType::UInt16,
                "Section header table index for the symbol",
            ),
        ],
    }
}

fn elf64_sym() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Sym".to_string(),
        description: "ELF64 Symbol Table Entry (24 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "st_name",
                FieldType::UInt32,
                "Symbol name (index into string table)",
            ),
            fd(
                "st_info",
                FieldType::UInt8,
                "Symbol type and binding (high 4 bits binding, low 4 bits type)",
            ),
            fd(
                "st_other",
                FieldType::UInt8,
                "Symbol visibility (low 2 bits)",
            ),
            fd(
                "st_shndx",
                FieldType::UInt16,
                "Section header table index for the symbol",
            ),
            fd("st_value", FieldType::UInt64, "Symbol value"),
            fd("st_size", FieldType::UInt64, "Symbol size"),
        ],
    }
}

fn elf32_rel() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Rel".to_string(),
        description: "ELF32 Relocation Entry without addend (8 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("r_offset", FieldType::UInt32, "Relocation target offset"),
            fd(
                "r_info",
                FieldType::UInt32,
                "Relocation type and symbol index (ELF32_R_TYPE / ELF32_R_SYM)",
            ),
        ],
    }
}

fn elf64_rel() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Rel".to_string(),
        description: "ELF64 Relocation Entry without addend (16 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("r_offset", FieldType::UInt64, "Relocation target offset"),
            fd(
                "r_info",
                FieldType::UInt64,
                "Relocation type and symbol index (ELF64_R_TYPE / ELF64_R_SYM)",
            ),
        ],
    }
}

fn elf32_rela() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Rela".to_string(),
        description: "ELF32 Relocation Entry with addend (12 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("r_offset", FieldType::UInt32, "Relocation target offset"),
            fd(
                "r_info",
                FieldType::UInt32,
                "Relocation type and symbol index (ELF32_R_TYPE / ELF32_R_SYM)",
            ),
            fd(
                "r_addend",
                FieldType::Int32,
                "Constant addend used to compute final value",
            ),
        ],
    }
}

fn elf64_rela() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Rela".to_string(),
        description: "ELF64 Relocation Entry with addend (24 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd("r_offset", FieldType::UInt64, "Relocation target offset"),
            fd(
                "r_info",
                FieldType::UInt64,
                "Relocation type and symbol index (ELF64_R_TYPE / ELF64_R_SYM)",
            ),
            fd(
                "r_addend",
                FieldType::Int64,
                "Constant addend used to compute final value",
            ),
        ],
    }
}

fn elf32_dyn() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Dyn".to_string(),
        description: "ELF32 Dynamic Section Entry (8 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "d_tag",
                FieldType::Int32,
                "Dynamic entry type (DT_NEEDED, DT_PLTRELSZ, etc.)",
            ),
            fd(
                "d_un",
                FieldType::UInt32,
                "Value or pointer (union d_val / d_ptr)",
            ),
        ],
    }
}

fn elf64_dyn() -> StructTemplate {
    StructTemplate {
        name: "Elf64_Dyn".to_string(),
        description: "ELF64 Dynamic Section Entry (16 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "d_tag",
                FieldType::Int64,
                "Dynamic entry type (DT_NEEDED, DT_PLTRELSZ, etc.)",
            ),
            fd(
                "d_un",
                FieldType::UInt64,
                "Value or pointer (union d_val / d_ptr)",
            ),
        ],
    }
}

fn elf_note() -> StructTemplate {
    StructTemplate {
        name: "Elf_Nhdr".to_string(),
        description: "ELF Note Header followed by name and desc, each padded to 4-byte alignment"
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ELF".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "n_namesz",
                FieldType::UInt32,
                "Length of note name (including trailing NUL)",
            ),
            fd("n_descsz", FieldType::UInt32, "Length of note descriptor"),
            fd(
                "n_type",
                FieldType::UInt32,
                "Note type (architecture-specific interpretation)",
            ),
            fd(
                "n_namesz_padded",
                FieldType::Computed {
                    expression: "(n_namesz + 3) / 4 * 4".to_string(),
                    display_type: Box::new(FieldType::UInt32),
                },
                "n_namesz rounded up to 4-byte alignment",
            ),
            fd(
                "name",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "n_namesz_padded".to_string(),
                },
                "Note name (NUL-terminated), padded to 4-byte alignment",
            ),
            fd(
                "n_descsz_padded",
                FieldType::Computed {
                    expression: "(n_descsz + 3) / 4 * 4".to_string(),
                    display_type: Box::new(FieldType::UInt32),
                },
                "n_descsz rounded up to 4-byte alignment",
            ),
            fd(
                "desc",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "n_descsz_padded".to_string(),
                },
                "Note descriptor, padded to 4-byte alignment",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Endianness, TemplateRegistry};

    macro_rules! define_put {
        ($name:ident, $ty:ty, $size:expr) => {
            fn $name(buf: &mut [u8], offset: usize, value: $ty, big_endian: bool) {
                let bytes = if big_endian {
                    value.to_be_bytes()
                } else {
                    value.to_le_bytes()
                };
                buf[offset..offset + $size].copy_from_slice(&bytes);
            }
        };
    }

    define_put!(put_u16, u16, 2);
    define_put!(put_u32, u32, 4);
    define_put!(put_u64, u64, 8);
    define_put!(put_i32, i32, 4);
    define_put!(put_i64, i64, 8);

    fn build_ehdr32(big_endian: bool) -> Vec<u8> {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        data[4] = 1;
        data[5] = if big_endian { 2 } else { 1 };
        data[6] = 1;
        data[7] = 0;
        put_u16(&mut data, 16, 2, big_endian);
        put_u16(&mut data, 18, 0x0014, big_endian);
        put_u32(&mut data, 20, 1, big_endian);
        put_u32(&mut data, 24, 0x1000_8000, big_endian);
        put_u32(&mut data, 28, 52, big_endian);
        put_u32(&mut data, 32, 0, big_endian);
        put_u32(&mut data, 36, 0, big_endian);
        put_u16(&mut data, 40, 52, big_endian);
        put_u16(&mut data, 42, 32, big_endian);
        put_u16(&mut data, 44, 1, big_endian);
        put_u16(&mut data, 46, 40, big_endian);
        put_u16(&mut data, 48, 1, big_endian);
        put_u16(&mut data, 50, 0, big_endian);
        data
    }

    fn build_ehdr64(big_endian: bool) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        data[4] = 2;
        data[5] = if big_endian { 2 } else { 1 };
        data[6] = 1;
        data[7] = 0;
        put_u16(&mut data, 16, 2, big_endian);
        put_u16(&mut data, 18, 0x0015, big_endian);
        put_u32(&mut data, 20, 1, big_endian);
        put_u64(&mut data, 24, 0x1_0000_8000, big_endian);
        put_u64(&mut data, 32, 64, big_endian);
        put_u64(&mut data, 40, 0, big_endian);
        put_u32(&mut data, 48, 0, big_endian);
        put_u16(&mut data, 52, 64, big_endian);
        put_u16(&mut data, 54, 56, big_endian);
        put_u16(&mut data, 56, 1, big_endian);
        put_u16(&mut data, 58, 64, big_endian);
        put_u16(&mut data, 60, 1, big_endian);
        put_u16(&mut data, 62, 0, big_endian);
        data
    }

    fn find_field(fields: &[super::super::ParsedField], name: &str) -> super::super::ParsedField {
        fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("field {name} not found"))
            .clone()
    }

    #[test]
    fn test_elf32_ehdr_little_endian() {
        let reg = TemplateRegistry::new();
        let data = build_ehdr32(false);
        let fields = reg.apply("Elf32_Ehdr", &data, 0).unwrap();
        let e_type = find_field(&fields, "e_type");
        assert!(
            e_type.display_value.contains("0x0002") || e_type.display_value.starts_with("2 "),
            "LE e_type display unexpected: {}",
            e_type.display_value
        );
        let e_machine = find_field(&fields, "e_machine");
        assert!(
            e_machine.display_value.contains("0x0014"),
            "LE e_machine display unexpected: {}",
            e_machine.display_value
        );
    }

    #[test]
    fn test_elf32_ehdr_big_endian_ppc() {
        let reg = TemplateRegistry::new();
        let data = build_ehdr32(true);
        let fields = reg.apply("Elf32_Ehdr", &data, 0).unwrap();
        let e_type = find_field(&fields, "e_type");
        assert!(
            e_type.display_value.starts_with("2 ") || e_type.display_value.contains("0x0002"),
            "BE e_type display unexpected: {}",
            e_type.display_value
        );
        let e_machine = find_field(&fields, "e_machine");
        assert!(
            e_machine.display_value.contains("0x0014")
                || e_machine.display_value.starts_with("20 "),
            "BE e_machine display unexpected: {}",
            e_machine.display_value
        );
        let e_entry = find_field(&fields, "e_entry");
        assert!(
            e_entry.display_value.contains("0x10008000"),
            "BE e_entry display unexpected: {}",
            e_entry.display_value
        );
        let e_phoff = find_field(&fields, "e_phoff");
        assert!(
            e_phoff.display_value.contains("0x00000034"),
            "BE e_phoff display unexpected: {}",
            e_phoff.display_value
        );
    }

    #[test]
    fn test_elf64_ehdr_big_endian() {
        let reg = TemplateRegistry::new();
        let data = build_ehdr64(true);
        let fields = reg.apply("Elf64_Ehdr", &data, 0).unwrap();
        let e_machine = find_field(&fields, "e_machine");
        assert!(
            e_machine.display_value.contains("0x0015"),
            "BE e_machine display unexpected: {}",
            e_machine.display_value
        );
        let e_entry = find_field(&fields, "e_entry");
        assert!(
            e_entry.display_value.contains("0x0000000100008000"),
            "BE e_entry display unexpected: {}",
            e_entry.display_value
        );
    }

    #[test]
    fn test_endianness_switch_marker_field_present() {
        let reg = TemplateRegistry::new();
        let data = build_ehdr32(true);
        let fields = reg.apply("Elf32_Ehdr", &data, 0).unwrap();
        let marker = find_field(&fields, "__ei_data_endianness");
        assert!(marker.display_value.starts_with("big"));
    }

    #[test]
    fn test_elf32_sym_registered_and_parsed() {
        let reg = TemplateRegistry::new();
        assert!(reg.get("Elf32_Sym").is_some());
        let mut data = vec![0u8; 16];
        put_u32(&mut data, 0, 0x1234_5678, false);
        put_u32(&mut data, 4, 0x0000_1000, false);
        put_u32(&mut data, 8, 0x0000_0040, false);
        data[12] = 0x12;
        data[13] = 0x00;
        put_u16(&mut data, 14, 0x0001, false);
        let fields = reg.apply("Elf32_Sym", &data, 0).unwrap();
        assert_eq!(fields.len(), 6);
        let st_name = find_field(&fields, "st_name");
        assert!(st_name.display_value.contains("0x12345678"));
        let st_value = find_field(&fields, "st_value");
        assert!(st_value.display_value.contains("0x00001000"));
        let st_size = find_field(&fields, "st_size");
        assert!(st_size.display_value.contains("0x00000040"));
        let st_info = find_field(&fields, "st_info");
        assert!(st_info.display_value.contains("0x12"));
        let st_shndx = find_field(&fields, "st_shndx");
        assert!(st_shndx.display_value.contains("0x0001"));
    }

    #[test]
    fn test_elf64_sym_registered_and_parsed() {
        let reg = TemplateRegistry::new();
        assert!(reg.get("Elf64_Sym").is_some());
        let mut data = vec![0u8; 24];
        put_u32(&mut data, 0, 0xAABB_CCDD, false);
        data[4] = 0x21;
        data[5] = 0x00;
        put_u16(&mut data, 6, 0x0002, false);
        put_u64(&mut data, 8, 0x0000_0000_4000_0000, false);
        put_u64(&mut data, 16, 0x0000_0000_0000_0100, false);
        let fields = reg.apply("Elf64_Sym", &data, 0).unwrap();
        assert_eq!(fields.len(), 6);
        let st_name = find_field(&fields, "st_name");
        assert!(st_name.display_value.contains("0xAABBCCDD"));
        let st_value = find_field(&fields, "st_value");
        assert!(st_value.display_value.contains("0x0000000040000000"));
        let st_size = find_field(&fields, "st_size");
        assert!(st_size.display_value.contains("0x0000000000000100"));
    }

    #[test]
    fn test_elf32_rel_parsed() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 8];
        put_u32(&mut data, 0, 0x0010_0000, false);
        put_u32(&mut data, 4, 0x0000_0101, false);
        let fields = reg.apply("Elf32_Rel", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        let r_offset = find_field(&fields, "r_offset");
        assert!(r_offset.display_value.contains("0x00100000"));
        let r_info = find_field(&fields, "r_info");
        assert!(r_info.display_value.contains("0x00000101"));
    }

    #[test]
    fn test_elf64_rel_parsed() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 16];
        put_u64(&mut data, 0, 0x0000_0000_0010_0000, false);
        put_u64(&mut data, 8, 0x0000_0001_0000_0007, false);
        let fields = reg.apply("Elf64_Rel", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        let r_offset = find_field(&fields, "r_offset");
        assert!(r_offset.display_value.contains("0x0000000000100000"));
        let r_info = find_field(&fields, "r_info");
        assert!(r_info.display_value.contains("0x0000000100000007"));
    }

    #[test]
    fn test_elf32_rela_parsed() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 12];
        put_u32(&mut data, 0, 0x0010_0000, false);
        put_u32(&mut data, 4, 0x0000_0101, false);
        put_i32(&mut data, 8, -16, false);
        let fields = reg.apply("Elf32_Rela", &data, 0).unwrap();
        assert_eq!(fields.len(), 3);
        let r_addend = find_field(&fields, "r_addend");
        assert!(
            r_addend.display_value.starts_with("-16 "),
            "r_addend unexpected: {}",
            r_addend.display_value
        );
    }

    #[test]
    fn test_elf64_rela_parsed_big_endian() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 24];
        put_u64(&mut data, 0, 0x0000_0000_0010_0000, true);
        put_u64(&mut data, 8, 0x0000_0001_0000_0007, true);
        put_i64(&mut data, 16, -32, true);
        let mut evaluator =
            super::super::eval::TemplateEvaluator::new(&data, 0, Endianness::Big, &reg);
        let template = reg.get("Elf64_Rela").unwrap();
        let fields = evaluator.evaluate_fields(&template.fields).unwrap();
        assert_eq!(fields.len(), 3);
        let r_offset = find_field(&fields, "r_offset");
        assert!(r_offset.display_value.contains("0x0000000000100000"));
        let r_addend = find_field(&fields, "r_addend");
        assert!(
            r_addend.display_value.starts_with("-32 "),
            "r_addend unexpected: {}",
            r_addend.display_value
        );
    }

    #[test]
    fn test_elf32_dyn_parsed() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 8];
        put_i32(&mut data, 0, 1, false);
        put_u32(&mut data, 4, 0x0000_1234, false);
        let fields = reg.apply("Elf32_Dyn", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        let d_tag = find_field(&fields, "d_tag");
        assert!(d_tag.display_value.starts_with("1 "));
        let d_un = find_field(&fields, "d_un");
        assert!(d_un.display_value.contains("0x00001234"));
    }

    #[test]
    fn test_elf64_dyn_parsed() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 16];
        put_i64(&mut data, 0, 6, false);
        put_u64(&mut data, 8, 0x0000_0000_DEAD_BEEF, false);
        let fields = reg.apply("Elf64_Dyn", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        let d_tag = find_field(&fields, "d_tag");
        assert!(d_tag.display_value.starts_with("6 "));
        let d_un = find_field(&fields, "d_un");
        assert!(d_un.display_value.contains("0x00000000DEADBEEF"));
    }

    #[test]
    fn test_elf_note_registered() {
        let reg = TemplateRegistry::new();
        assert!(reg.get("Elf_Nhdr").is_some());
        let template = reg.get("Elf_Nhdr").unwrap();
        assert_eq!(template.category.as_deref(), Some("ELF"));
        assert_eq!(template.fields[0].name, "n_namesz");
        assert_eq!(template.fields[1].name, "n_descsz");
        assert_eq!(template.fields[2].name, "n_type");
        assert!(template.fields.iter().any(|f| f.name == "name"));
        assert!(template.fields.iter().any(|f| f.name == "desc"));
    }

    #[test]
    fn test_elf_note_parsed_with_padding() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 12 + 8 + 4];
        put_u32(&mut data, 0, 4, false);
        put_u32(&mut data, 4, 4, false);
        put_u32(&mut data, 8, 3, false);
        data[12] = b'G';
        data[13] = b'N';
        data[14] = b'U';
        data[15] = 0x00;
        data[16] = 0xDE;
        data[17] = 0xAD;
        data[18] = 0xBE;
        data[19] = 0xEF;
        let fields = reg.apply("Elf_Nhdr", &data, 0).unwrap();
        let n_namesz = find_field(&fields, "n_namesz");
        assert!(n_namesz.display_value.contains("0x00000004"));
        let n_type = find_field(&fields, "n_type");
        assert!(n_type.display_value.contains("0x00000003"));
        let name = find_field(&fields, "name");
        assert_eq!(name.children.len(), 4);
        let desc = find_field(&fields, "desc");
        assert_eq!(desc.children.len(), 4);
    }

    #[test]
    fn test_elf_note_padding_round_up() {
        let reg = TemplateRegistry::new();
        let mut data = vec![0u8; 12 + 8 + 8];
        put_u32(&mut data, 0, 5, false);
        put_u32(&mut data, 4, 5, false);
        put_u32(&mut data, 8, 1, false);
        data[12..17].copy_from_slice(b"CORE\0");
        data[17] = 0;
        data[18] = 0;
        data[19] = 0;
        data[20..25].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        data[25] = 0;
        data[26] = 0;
        data[27] = 0;
        let fields = reg.apply("Elf_Nhdr", &data, 0).unwrap();
        let name = find_field(&fields, "name");
        assert_eq!(name.children.len(), 8);
        let desc = find_field(&fields, "desc");
        assert_eq!(desc.children.len(), 8);
    }

    #[test]
    fn test_all_elf_templates_registered() {
        let reg = TemplateRegistry::new();
        let names = [
            "Elf32_Ehdr",
            "Elf64_Ehdr",
            "Elf32_Phdr",
            "Elf64_Phdr",
            "Elf32_Shdr",
            "Elf64_Shdr",
            "Elf32_Sym",
            "Elf64_Sym",
            "Elf32_Rel",
            "Elf64_Rel",
            "Elf32_Rela",
            "Elf64_Rela",
            "Elf32_Dyn",
            "Elf64_Dyn",
            "Elf_Nhdr",
        ];
        for name in names {
            assert!(reg.get(name).is_some(), "template {name} not registered");
        }
    }
}
