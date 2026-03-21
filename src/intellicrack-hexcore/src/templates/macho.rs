use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(mach_header());
    registry.register(mach_header_64());
    registry.register(load_command());
    registry.register(segment_command_64());
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

fn mach_header() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER".to_string(),
        description: "Mach-O 32-bit header (28 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xCE, 0xFA, 0xED, 0xFE],
        }),
        fields: vec![
            fd("magic", FieldType::UInt32, "Mach-O magic (0xFEEDFACE or 0xCEFAEDFE)"),
            fd("cputype", FieldType::Int32, "CPU type identifier"),
            fd("cpusubtype", FieldType::Int32, "CPU subtype identifier"),
            fd("filetype", FieldType::UInt32, "Type of file (MH_EXECUTE=2, MH_DYLIB=6, etc.)"),
            fd("ncmds", FieldType::UInt32, "Number of load commands"),
            fd("sizeofcmds", FieldType::UInt32, "Size of all load commands in bytes"),
            fd("flags", FieldType::UInt32, "Flags (MH_NOUNDEFS, MH_PIE, etc.)"),
        ],
    }
}

fn mach_header_64() -> StructTemplate {
    StructTemplate {
        name: "MACH_HEADER_64".to_string(),
        description: "Mach-O 64-bit header (32 bytes at offset 0)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0xCF, 0xFA, 0xED, 0xFE],
        }),
        fields: vec![
            fd("magic", FieldType::UInt32, "Mach-O 64-bit magic (0xFEEDFACF or 0xCFFAEDFE)"),
            fd("cputype", FieldType::Int32, "CPU type identifier"),
            fd("cpusubtype", FieldType::Int32, "CPU subtype identifier"),
            fd("filetype", FieldType::UInt32, "Type of file"),
            fd("ncmds", FieldType::UInt32, "Number of load commands"),
            fd("sizeofcmds", FieldType::UInt32, "Size of all load commands in bytes"),
            fd("flags", FieldType::UInt32, "Flags"),
            fd("reserved", FieldType::UInt32, "Reserved (64-bit padding)"),
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
            fd("cmd", FieldType::UInt32, "Load command type (LC_SEGMENT_64=0x19, etc.)"),
            fd("cmdsize", FieldType::UInt32, "Total size of command including data"),
        ],
    }
}

fn segment_command_64() -> StructTemplate {
    StructTemplate {
        name: "SEGMENT_COMMAND_64".to_string(),
        description: "Mach-O 64-bit segment command (72 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Mach-O".to_string()),
        magic_detection: None,
        fields: vec![
            fd("cmd", FieldType::UInt32, "LC_SEGMENT_64 (0x19)"),
            fd("cmdsize", FieldType::UInt32, "Size of this command"),
            fd("segname", FieldType::FixedString(16), "Segment name (__TEXT, __DATA, etc.)"),
            fd("vmaddr", FieldType::UInt64, "Virtual memory address"),
            fd("vmsize", FieldType::UInt64, "Virtual memory size"),
            fd("fileoff", FieldType::UInt64, "File offset of this segment"),
            fd("filesize", FieldType::UInt64, "File size of this segment"),
            fd("maxprot", FieldType::Int32, "Maximum VM protection"),
            fd("initprot", FieldType::Int32, "Initial VM protection"),
            fd("nsects", FieldType::UInt32, "Number of sections in this segment"),
            fd("flags", FieldType::UInt32, "Segment flags"),
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
        assert!(list.iter().any(|(name, _)| name == "MACH_HEADER_64"));
        assert!(list.iter().any(|(name, _)| name == "LOAD_COMMAND"));
        assert!(list.iter().any(|(name, _)| name == "SEGMENT_COMMAND_64"));
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
}
