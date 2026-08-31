use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(guid_template());
    registry.register(filetime_template());
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

fn guid_template() -> StructTemplate {
    StructTemplate {
        name: "GUID".to_string(),
        description: "Windows GUID / UUID (16 bytes)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Common".to_string()),
        magic_detection: None,
        fields: vec![
            fd("Data1", FieldType::UInt32, "First 4 bytes (little-endian)"),
            fd("Data2", FieldType::UInt16, "Next 2 bytes (little-endian)"),
            fd("Data3", FieldType::UInt16, "Next 2 bytes (little-endian)"),
            fd(
                "Data4",
                FieldType::Bytes(8),
                "Last 8 bytes (big-endian order)",
            ),
        ],
    }
}

fn filetime_template() -> StructTemplate {
    StructTemplate {
        name: "FILETIME".to_string(),
        description: "Windows FILETIME (8 bytes, 100ns intervals since 1601-01-01)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("Common".to_string()),
        magic_detection: None,
        fields: vec![
            fd("dwLowDateTime", FieldType::UInt32, "Low-order 32 bits"),
            fd("dwHighDateTime", FieldType::UInt32, "High-order 32 bits"),
        ],
    }
}
