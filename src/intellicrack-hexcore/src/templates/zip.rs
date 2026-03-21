use super::{Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(zip_local_file_header());
    registry.register(zip_central_directory());
    registry.register(zip_end_of_central_directory());
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

fn zip_local_file_header() -> StructTemplate {
    StructTemplate {
        name: "ZIP_LOCAL_FILE_HEADER".to_string(),
        description: "ZIP Local File Header (30 bytes fixed)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x03, 0x04],
        }),
        fields: vec![
            fd("signature", FieldType::UInt32, "Local file header signature (0x04034B50)"),
            fd("version_needed", FieldType::UInt16, "Version needed to extract"),
            fd("general_purpose_flags", FieldType::UInt16, "General purpose bit flags"),
            fd("compression_method", FieldType::UInt16, "Compression method"),
            fd("last_mod_time", FieldType::UInt16, "Last modification time (DOS)"),
            fd("last_mod_date", FieldType::UInt16, "Last modification date (DOS)"),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd("compressed_size", FieldType::UInt32, "Compressed size"),
            fd("uncompressed_size", FieldType::UInt32, "Uncompressed size"),
            fd("filename_length", FieldType::UInt16, "File name length"),
            fd("extra_field_length", FieldType::UInt16, "Extra field length"),
        ],
    }
}

fn zip_central_directory() -> StructTemplate {
    StructTemplate {
        name: "ZIP_CENTRAL_DIRECTORY".to_string(),
        description: "ZIP Central Directory File Header (46 bytes fixed)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: None,
        fields: vec![
            fd("signature", FieldType::UInt32, "Central directory signature (0x02014B50)"),
            fd("version_made_by", FieldType::UInt16, "Version made by"),
            fd("version_needed", FieldType::UInt16, "Version needed to extract"),
            fd("general_purpose_flags", FieldType::UInt16, "General purpose bit flags"),
            fd("compression_method", FieldType::UInt16, "Compression method"),
            fd("last_mod_time", FieldType::UInt16, "Last modification time (DOS)"),
            fd("last_mod_date", FieldType::UInt16, "Last modification date (DOS)"),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd("compressed_size", FieldType::UInt32, "Compressed size"),
            fd("uncompressed_size", FieldType::UInt32, "Uncompressed size"),
            fd("filename_length", FieldType::UInt16, "File name length"),
            fd("extra_field_length", FieldType::UInt16, "Extra field length"),
            fd("file_comment_length", FieldType::UInt16, "File comment length"),
            fd("disk_number_start", FieldType::UInt16, "Disk number start"),
            fd("internal_file_attributes", FieldType::UInt16, "Internal file attributes"),
            fd("external_file_attributes", FieldType::UInt32, "External file attributes"),
            fd("local_header_offset", FieldType::UInt32, "Relative offset of local header"),
        ],
    }
}

fn zip_end_of_central_directory() -> StructTemplate {
    StructTemplate {
        name: "ZIP_END_OF_CENTRAL_DIRECTORY".to_string(),
        description: "ZIP End of Central Directory Record (22 bytes fixed)".to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: None,
        fields: vec![
            fd("signature", FieldType::UInt32, "End of central directory signature (0x06054B50)"),
            fd("disk_number", FieldType::UInt16, "Number of this disk"),
            fd("disk_with_central_dir", FieldType::UInt16, "Disk where central directory starts"),
            fd("num_entries_this_disk", FieldType::UInt16, "Number of central directory entries on this disk"),
            fd("num_entries_total", FieldType::UInt16, "Total number of central directory entries"),
            fd("central_dir_size", FieldType::UInt32, "Size of central directory"),
            fd("central_dir_offset", FieldType::UInt32, "Offset of start of central directory"),
            fd("comment_length", FieldType::UInt16, "ZIP file comment length"),
        ],
    }
}
