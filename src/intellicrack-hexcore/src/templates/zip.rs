use super::{
    ConditionOp, Endianness, FieldDefinition, FieldType, StructTemplate, TemplateRegistry,
};

pub fn register_templates(registry: &mut TemplateRegistry) {
    registry.register(zip_local_file_header());
    registry.register(zip_central_directory());
    registry.register(zip_end_of_central_directory());
    registry.register(zip64_eocd_record());
    registry.register(zip64_eocd_locator());
    registry.register(zip64_extra_field());
    registry.register(zip_data_descriptor());
    registry.register(zip64_data_descriptor());
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
            fd(
                "signature",
                FieldType::UInt32,
                "Local file header signature (0x04034B50)",
            ),
            fd(
                "version_needed",
                FieldType::UInt16,
                "Version needed to extract",
            ),
            fd(
                "general_purpose_flags",
                FieldType::UInt16,
                "General purpose bit flags",
            ),
            fd(
                "compression_method",
                FieldType::UInt16,
                "Compression method",
            ),
            fd(
                "last_mod_time",
                FieldType::UInt16,
                "Last modification time (DOS)",
            ),
            fd(
                "last_mod_date",
                FieldType::UInt16,
                "Last modification date (DOS)",
            ),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd("compressed_size", FieldType::UInt32, "Compressed size"),
            fd("uncompressed_size", FieldType::UInt32, "Uncompressed size"),
            fd("filename_length", FieldType::UInt16, "File name length"),
            fd(
                "extra_field_length",
                FieldType::UInt16,
                "Extra field length",
            ),
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
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x01, 0x02],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "Central directory signature (0x02014B50)",
            ),
            fd("version_made_by", FieldType::UInt16, "Version made by"),
            fd(
                "version_needed",
                FieldType::UInt16,
                "Version needed to extract",
            ),
            fd(
                "general_purpose_flags",
                FieldType::UInt16,
                "General purpose bit flags",
            ),
            fd(
                "compression_method",
                FieldType::UInt16,
                "Compression method",
            ),
            fd(
                "last_mod_time",
                FieldType::UInt16,
                "Last modification time (DOS)",
            ),
            fd(
                "last_mod_date",
                FieldType::UInt16,
                "Last modification date (DOS)",
            ),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd("compressed_size", FieldType::UInt32, "Compressed size"),
            fd("uncompressed_size", FieldType::UInt32, "Uncompressed size"),
            fd("filename_length", FieldType::UInt16, "File name length"),
            fd(
                "extra_field_length",
                FieldType::UInt16,
                "Extra field length",
            ),
            fd(
                "file_comment_length",
                FieldType::UInt16,
                "File comment length",
            ),
            fd("disk_number_start", FieldType::UInt16, "Disk number start"),
            fd(
                "internal_file_attributes",
                FieldType::UInt16,
                "Internal file attributes",
            ),
            fd(
                "external_file_attributes",
                FieldType::UInt32,
                "External file attributes",
            ),
            fd(
                "local_header_offset",
                FieldType::UInt32,
                "Relative offset of local header",
            ),
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
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x05, 0x06],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "End of central directory signature (0x06054B50)",
            ),
            fd("disk_number", FieldType::UInt16, "Number of this disk"),
            fd(
                "disk_with_central_dir",
                FieldType::UInt16,
                "Disk where central directory starts",
            ),
            fd(
                "num_entries_this_disk",
                FieldType::UInt16,
                "Number of central directory entries on this disk",
            ),
            fd(
                "num_entries_total",
                FieldType::UInt16,
                "Total number of central directory entries",
            ),
            fd(
                "central_dir_size",
                FieldType::UInt32,
                "Size of central directory",
            ),
            fd(
                "central_dir_offset",
                FieldType::UInt32,
                "Offset of start of central directory",
            ),
            fd(
                "comment_length",
                FieldType::UInt16,
                "ZIP file comment length",
            ),
        ],
    }
}

fn zip64_eocd_record() -> StructTemplate {
    StructTemplate {
        name: "ZIP64_EOCD_RECORD".to_string(),
        description:
            "ZIP64 End of Central Directory Record (56 bytes fixed + variable extension). \
             Signature 0x06064B50. All fields little-endian. The size_of_zip64_eocd field is \
             the size of this record excluding the first 12 bytes (signature and size field). \
             A variable-length zip64_extensible_data_sector follows the fixed header."
                .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x06, 0x06],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "ZIP64 end of central directory signature (0x06064B50)",
            ),
            fd(
                "size_of_zip64_eocd",
                FieldType::UInt64,
                "Size of ZIP64 end of central directory record (excluding leading 12 bytes)",
            ),
            fd("version_made_by", FieldType::UInt16, "Version made by"),
            fd(
                "version_needed",
                FieldType::UInt16,
                "Version needed to extract",
            ),
            fd(
                "number_of_this_disk",
                FieldType::UInt32,
                "Number of this disk",
            ),
            fd(
                "disk_with_start_of_cd",
                FieldType::UInt32,
                "Number of the disk with the start of the central directory",
            ),
            fd(
                "total_entries_on_this_disk",
                FieldType::UInt64,
                "Total number of entries in the central directory on this disk",
            ),
            fd(
                "total_entries",
                FieldType::UInt64,
                "Total number of entries in the central directory",
            ),
            fd(
                "size_of_cd",
                FieldType::UInt64,
                "Size of the central directory",
            ),
            fd(
                "offset_of_cd",
                FieldType::UInt64,
                "Offset of start of central directory with respect to the starting disk number",
            ),
        ],
    }
}

fn zip64_eocd_locator() -> StructTemplate {
    StructTemplate {
        name: "ZIP64_EOCD_LOCATOR".to_string(),
        description: "ZIP64 End of Central Directory Locator (20 bytes fixed). \
                      Signature 0x07064B50. All fields little-endian. Located immediately \
                      before the standard End of Central Directory Record."
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x06, 0x07],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "ZIP64 end of central directory locator signature (0x07064B50)",
            ),
            fd(
                "disk_with_zip64_eocd",
                FieldType::UInt32,
                "Number of the disk with the start of the ZIP64 end of central directory",
            ),
            fd(
                "offset_of_zip64_eocd",
                FieldType::UInt64,
                "Relative offset of the ZIP64 end of central directory record",
            ),
            fd(
                "total_number_of_disks",
                FieldType::UInt32,
                "Total number of disks",
            ),
        ],
    }
}

fn zip64_extra_field() -> StructTemplate {
    StructTemplate {
        name: "ZIP64_EXTRA_FIELD".to_string(),
        description: "ZIP64 Extended Information Extra Field (header ID 0x0001). \
                      All fields little-endian. Per APPNOTE.TXT section 4.5.3, the four \
                      conditional fields are only present in order up to data_size bytes: \
                      original_size requires data_size >= 8, compressed_size requires \
                      data_size >= 16, relative_header_offset requires data_size >= 24, and \
                      disk_start_number requires data_size >= 28. Each field is gated on the \
                      declared data_size so a short block (e.g. data_size = 8, only \
                      original_size present) does not read past its own boundary into \
                      unrelated trailing bytes."
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: None,
        fields: vec![
            fd(
                "header_id",
                FieldType::UInt16,
                "ZIP64 extended information header ID (0x0001)",
            ),
            fd(
                "data_size",
                FieldType::UInt16,
                "Size of this extra field block (excluding header_id and data_size)",
            ),
            fd(
                "original_size_present",
                FieldType::Conditional {
                    condition_field: "data_size".to_string(),
                    condition_value: 8,
                    condition_op: ConditionOp::Ge,
                    fields: vec![fd(
                        "original_size",
                        FieldType::UInt64,
                        "Original uncompressed file size (present if entry uncompressed_size == 0xFFFFFFFF)",
                    )],
                },
                "Present when data_size >= 8",
            ),
            fd(
                "compressed_size_present",
                FieldType::Conditional {
                    condition_field: "data_size".to_string(),
                    condition_value: 16,
                    condition_op: ConditionOp::Ge,
                    fields: vec![fd(
                        "compressed_size",
                        FieldType::UInt64,
                        "Compressed file size (present if entry compressed_size == 0xFFFFFFFF)",
                    )],
                },
                "Present when data_size >= 16",
            ),
            fd(
                "relative_header_offset_present",
                FieldType::Conditional {
                    condition_field: "data_size".to_string(),
                    condition_value: 24,
                    condition_op: ConditionOp::Ge,
                    fields: vec![fd(
                        "relative_header_offset",
                        FieldType::UInt64,
                        "Offset of local header record (present if entry local_header_offset == 0xFFFFFFFF)",
                    )],
                },
                "Present when data_size >= 24",
            ),
            fd(
                "disk_start_number_present",
                FieldType::Conditional {
                    condition_field: "data_size".to_string(),
                    condition_value: 28,
                    condition_op: ConditionOp::Ge,
                    fields: vec![fd(
                        "disk_start_number",
                        FieldType::UInt32,
                        "Number of the disk on which this file starts (present if entry disk_number_start == 0xFFFF)",
                    )],
                },
                "Present when data_size >= 28",
            ),
        ],
    }
}

fn zip_data_descriptor() -> StructTemplate {
    StructTemplate {
        name: "ZIP_DATA_DESCRIPTOR".to_string(),
        description: "ZIP Data Descriptor (16 bytes with signature). \
                      Signature 0x08074B50 is technically optional per APPNOTE.TXT but is \
                      almost always present. Follows the compressed file data when bit 3 of \
                      the local file header general-purpose flags is set. All fields \
                      little-endian. Use ZIP64_DATA_DESCRIPTOR when the archive is ZIP64."
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x07, 0x08],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "Data descriptor signature (0x08074B50, optional per spec but typically present)",
            ),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd(
                "compressed_size",
                FieldType::UInt32,
                "Compressed size of the file data",
            ),
            fd(
                "uncompressed_size",
                FieldType::UInt32,
                "Uncompressed size of the file data",
            ),
        ],
    }
}

fn zip64_data_descriptor() -> StructTemplate {
    StructTemplate {
        name: "ZIP64_DATA_DESCRIPTOR".to_string(),
        description: "ZIP64 Data Descriptor (24 bytes with signature). \
                      Signature 0x08074B50 is technically optional per APPNOTE.TXT but is \
                      almost always present. Used in place of ZIP_DATA_DESCRIPTOR when the \
                      archive is ZIP64 (compressed_size and uncompressed_size are 8 bytes). \
                      Follows the compressed file data when bit 3 of the local file header \
                      general-purpose flags is set. All fields little-endian."
            .to_string(),
        default_endianness: Endianness::Little,
        version: None,
        author: None,
        category: Some("ZIP".to_string()),
        magic_detection: Some(super::MagicDetection {
            offset: 0,
            bytes: vec![0x50, 0x4B, 0x07, 0x08],
        }),
        fields: vec![
            fd(
                "signature",
                FieldType::UInt32,
                "Data descriptor signature (0x08074B50, optional per spec but typically present)",
            ),
            fd("crc32", FieldType::UInt32, "CRC-32 of uncompressed data"),
            fd(
                "compressed_size",
                FieldType::UInt64,
                "Compressed size of the file data (ZIP64, 8 bytes)",
            ),
            fd(
                "uncompressed_size",
                FieldType::UInt64,
                "Uncompressed size of the file data (ZIP64, 8 bytes)",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::TemplateRegistry;

    #[test]
    fn test_zip_templates_registered() {
        let reg = TemplateRegistry::new();
        let list = reg.list();
        assert!(list.iter().any(|(name, _)| name == "ZIP_LOCAL_FILE_HEADER"));
        assert!(list.iter().any(|(name, _)| name == "ZIP_CENTRAL_DIRECTORY"));
        assert!(list
            .iter()
            .any(|(name, _)| name == "ZIP_END_OF_CENTRAL_DIRECTORY"));
        assert!(list.iter().any(|(name, _)| name == "ZIP64_EOCD_RECORD"));
        assert!(list.iter().any(|(name, _)| name == "ZIP64_EOCD_LOCATOR"));
        assert!(list.iter().any(|(name, _)| name == "ZIP64_EXTRA_FIELD"));
        assert!(list.iter().any(|(name, _)| name == "ZIP_DATA_DESCRIPTOR"));
        assert!(list.iter().any(|(name, _)| name == "ZIP64_DATA_DESCRIPTOR"));
    }

    /// Gate for finding #55: `ZIP_CENTRAL_DIRECTORY` and
    /// `ZIP_END_OF_CENTRAL_DIRECTORY` each have a genuine unique 4-byte
    /// signature per APPNOTE.TXT and must declare `magic_detection` like
    /// every other ZIP record type with a stable signature, so a
    /// magic/signature scanner can locate them at an arbitrary offset.
    ///
    /// Mutation caught: reverting either `magic_detection` back to `None`
    /// makes the corresponding `.unwrap()` panic.
    #[test]
    fn test_central_directory_and_eocd_have_magic_detection() {
        let reg = TemplateRegistry::new();

        let cd = reg.get("ZIP_CENTRAL_DIRECTORY").unwrap();
        let cd_magic = cd
            .magic_detection
            .as_ref()
            .expect("ZIP_CENTRAL_DIRECTORY must declare magic_detection");
        assert_eq!(cd_magic.offset, 0);
        assert_eq!(cd_magic.bytes, vec![0x50, 0x4B, 0x01, 0x02]);

        let eocd = reg.get("ZIP_END_OF_CENTRAL_DIRECTORY").unwrap();
        let eocd_magic = eocd
            .magic_detection
            .as_ref()
            .expect("ZIP_END_OF_CENTRAL_DIRECTORY must declare magic_detection");
        assert_eq!(eocd_magic.offset, 0);
        assert_eq!(eocd_magic.bytes, vec![0x50, 0x4B, 0x05, 0x06]);
    }

    fn put_u16_le(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u32_le(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u64_le(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn test_zip64_eocd_record_roundtrip() {
        let mut data = Vec::with_capacity(56);
        put_u32_le(&mut data, 0x0606_4B50);
        put_u64_le(&mut data, 44);
        put_u16_le(&mut data, 0x002D);
        put_u16_le(&mut data, 0x002D);
        put_u32_le(&mut data, 0);
        put_u32_le(&mut data, 0);
        put_u64_le(&mut data, 5);
        put_u64_le(&mut data, 5);
        put_u64_le(&mut data, 200);
        put_u64_le(&mut data, 1024);

        assert_eq!(data.len(), 56);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP64_EOCD_RECORD", &data, 0).unwrap();
        assert_eq!(fields.len(), 10);
        assert_eq!(fields[0].name, "signature");
        assert!(fields[0].display_value.contains("06064B50"));
        assert_eq!(fields[1].name, "size_of_zip64_eocd");
        assert!(fields[1].display_value.contains("44"));
        assert_eq!(fields[6].name, "total_entries_on_this_disk");
        assert!(fields[6].display_value.starts_with("5 "));
        assert_eq!(fields[7].name, "total_entries");
        assert!(fields[7].display_value.starts_with("5 "));
        assert_eq!(fields[8].name, "size_of_cd");
        assert!(fields[8].display_value.starts_with("200 "));
        assert_eq!(fields[9].name, "offset_of_cd");
        assert!(fields[9].display_value.starts_with("1024 "));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(total_size, 56);
    }

    #[test]
    fn test_zip64_eocd_locator_roundtrip() {
        let mut data = Vec::with_capacity(20);
        put_u32_le(&mut data, 0x0706_4B50);
        put_u32_le(&mut data, 0);
        put_u64_le(&mut data, 4_294_967_296);
        put_u32_le(&mut data, 1);

        assert_eq!(data.len(), 20);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP64_EOCD_LOCATOR", &data, 0).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "signature");
        assert!(fields[0].display_value.contains("07064B50"));
        assert_eq!(fields[2].name, "offset_of_zip64_eocd");
        assert!(fields[2].display_value.starts_with("4294967296 "));
        assert_eq!(fields[3].name, "total_number_of_disks");
        assert!(fields[3].display_value.starts_with("1 "));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(total_size, 20);
    }

    #[test]
    fn test_zip64_extra_field_roundtrip() {
        let mut data = Vec::with_capacity(32);
        put_u16_le(&mut data, 0x0001);
        put_u16_le(&mut data, 28);
        put_u64_le(&mut data, 8_000_000_000);
        put_u64_le(&mut data, 5_000_000_000);
        put_u64_le(&mut data, 9_000_000_000);
        put_u32_le(&mut data, 42);

        assert_eq!(data.len(), 32);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP64_EXTRA_FIELD", &data, 0).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, "header_id");
        assert!(fields[0].display_value.contains("0001"));
        assert_eq!(fields[1].name, "data_size");
        assert!(fields[1].display_value.contains("28"));
        assert_eq!(fields[2].name, "original_size");
        assert!(fields[2].display_value.starts_with("8000000000 "));
        assert_eq!(fields[3].name, "compressed_size");
        assert!(fields[3].display_value.starts_with("5000000000 "));
        assert_eq!(fields[4].name, "relative_header_offset");
        assert!(fields[4].display_value.starts_with("9000000000 "));
        assert_eq!(fields[5].name, "disk_start_number");
        assert!(fields[5].display_value.starts_with("42 "));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(total_size, 32);
    }

    /// Gate for finding #56: when `data_size == 8` (only `original_size`
    /// present, the common case for a local-file-header zip64 extra field),
    /// the template must stop after `original_size` and must NOT read the
    /// following unrelated bytes as `compressed_size`,
    /// `relative_header_offset`, or `disk_start_number`.
    ///
    /// Mutation caught: reverting the four trailing fields from
    /// `Conditional` back to unconditional `fd(...)` calls makes
    /// `fields.len()` become 6 instead of 3, `total_size` become 32 instead
    /// of 12, and `compressed_size` would be found with a fabricated value
    /// derived from the poison/NTFS-header bytes rather than being absent.
    #[test]
    fn test_zip64_extra_field_partial_data_size_stops_at_boundary() {
        let mut data = Vec::with_capacity(32);
        put_u16_le(&mut data, 0x0001); // header_id
        put_u16_le(&mut data, 8); // data_size = 8: only original_size present
        put_u64_le(&mut data, 123_456_789); // original_size

        // Poison bytes: an unrelated subsequent extra-field record (e.g. an
        // NTFS extra field, header_id 0x000A) that must NOT be consumed or
        // mislabeled as compressed_size/relative_header_offset/disk_start_number.
        put_u16_le(&mut data, 0x000A);
        put_u16_le(&mut data, 0xDEAD);
        put_u64_le(&mut data, 0xFFFF_FFFF_FFFF_FFFF);
        put_u32_le(&mut data, 0xBAAD_F00D);

        assert_eq!(data.len(), 12 + 16);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP64_EXTRA_FIELD", &data, 0).unwrap();

        assert_eq!(
            fields.len(),
            3,
            "only header_id, data_size, and original_size may be present when data_size == 8"
        );
        assert_eq!(fields[0].name, "header_id");
        assert_eq!(fields[1].name, "data_size");
        assert_eq!(fields[2].name, "original_size");
        assert!(fields[2].display_value.starts_with("123456789 "));

        assert!(
            !fields.iter().any(|f| f.name == "compressed_size"),
            "compressed_size must not be fabricated from bytes belonging to the next extra field"
        );
        assert!(!fields.iter().any(|f| f.name == "relative_header_offset"));
        assert!(!fields.iter().any(|f| f.name == "disk_start_number"));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(
            total_size, 12,
            "the template must consume exactly header_id + data_size + original_size (12 bytes)"
        );
    }

    #[test]
    fn test_zip_data_descriptor_roundtrip() {
        let mut data = Vec::with_capacity(16);
        put_u32_le(&mut data, 0x0807_4B50);
        put_u32_le(&mut data, 305_419_896);
        put_u32_le(&mut data, 4660);
        put_u32_le(&mut data, 22136);

        assert_eq!(data.len(), 16);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP_DATA_DESCRIPTOR", &data, 0).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "signature");
        assert!(fields[0].display_value.contains("08074B50"));
        assert_eq!(fields[1].name, "crc32");
        assert!(fields[1].display_value.starts_with("305419896 "));
        assert_eq!(fields[2].name, "compressed_size");
        assert!(fields[2].display_value.starts_with("4660 "));
        assert_eq!(fields[3].name, "uncompressed_size");
        assert!(fields[3].display_value.starts_with("22136 "));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(total_size, 16);
    }

    #[test]
    fn test_zip64_data_descriptor_roundtrip() {
        let mut data = Vec::with_capacity(24);
        put_u32_le(&mut data, 0x0807_4B50);
        put_u32_le(&mut data, 2_882_400_018);
        put_u64_le(&mut data, 6_000_000_000);
        put_u64_le(&mut data, 7_500_000_000);

        assert_eq!(data.len(), 24);

        let reg = TemplateRegistry::new();
        let fields = reg.apply("ZIP64_DATA_DESCRIPTOR", &data, 0).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "signature");
        assert!(fields[0].display_value.contains("08074B50"));
        assert_eq!(fields[1].name, "crc32");
        assert!(fields[1].display_value.starts_with("2882400018 "));
        assert_eq!(fields[2].name, "compressed_size");
        assert!(fields[2].display_value.starts_with("6000000000 "));
        assert_eq!(fields[3].name, "uncompressed_size");
        assert!(fields[3].display_value.starts_with("7500000000 "));

        let total_size: usize = fields.iter().map(|f| f.size).sum();
        assert_eq!(total_size, 24);
    }
}
