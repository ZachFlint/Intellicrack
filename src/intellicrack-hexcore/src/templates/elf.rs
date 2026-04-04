use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(elf32_ehdr());
    registry.register(elf64_ehdr());
    registry.register(elf32_phdr());
    registry.register(elf64_phdr());
    registry.register(elf32_shdr());
    registry.register(elf64_shdr());
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

fn elf32_ehdr() -> StructTemplate {
    StructTemplate {
        name: "Elf32_Ehdr".to_string(),
        description: "ELF32 File Header (52 bytes)".to_string(),
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
        description: "ELF64 File Header (64 bytes)".to_string(),
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
