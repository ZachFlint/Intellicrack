pub mod common;
pub mod elf;
pub mod macho;
pub mod pe;
pub mod zip;

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone)]
pub enum FieldType {
    UInt8,
    Int8,
    UInt16,
    Int16,
    UInt32,
    Int32,
    UInt64,
    Int64,
    Float32,
    Float64,
    Bytes(usize),
    FixedString(usize),
    Array(Box<FieldType>, usize),
}

#[derive(Debug, Clone)]
pub struct FieldDefinition {
    pub name: String,
    pub field_type: FieldType,
    pub endianness: Option<Endianness>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct StructTemplate {
    pub name: String,
    pub description: String,
    pub fields: Vec<FieldDefinition>,
    pub default_endianness: Endianness,
}

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub raw_bytes: Vec<u8>,
    pub display_value: String,
    pub children: Vec<ParsedField>,
}

#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("template not found: {0}")]
    NotFound(String),
    #[error("insufficient data at offset {offset}: need {needed} bytes, have {available}")]
    InsufficientData {
        offset: usize,
        needed: usize,
        available: usize,
    },
}

pub struct TemplateRegistry {
    templates: HashMap<String, StructTemplate>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            templates: HashMap::new(),
        };
        register_builtins(&mut registry);
        registry
    }

    pub fn register(&mut self, template: StructTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn get(&self, name: &str) -> Option<&StructTemplate> {
        self.templates.get(name)
    }

    pub fn list(&self) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = self
            .templates
            .iter()
            .map(|(k, v)| (k.clone(), v.description.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    pub fn apply(
        &self,
        name: &str,
        data: &[u8],
        offset: usize,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let template = self
            .templates
            .get(name)
            .ok_or_else(|| TemplateError::NotFound(name.to_string()))?;

        parse_fields(&template.fields, data, offset, template.default_endianness)
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn field_size(ft: &FieldType) -> usize {
    match ft {
        FieldType::UInt8 | FieldType::Int8 => 1,
        FieldType::UInt16 | FieldType::Int16 => 2,
        FieldType::UInt32 | FieldType::Int32 | FieldType::Float32 => 4,
        FieldType::UInt64 | FieldType::Int64 | FieldType::Float64 => 8,
        FieldType::Bytes(n) | FieldType::FixedString(n) => *n,
        FieldType::Array(inner, count) => field_size(inner) * count,
    }
}

fn parse_fields(
    fields: &[FieldDefinition],
    data: &[u8],
    base_offset: usize,
    default_endian: Endianness,
) -> Result<Vec<ParsedField>, TemplateError> {
    let mut results = Vec::new();
    let mut current_offset = base_offset;

    for field in fields {
        let endian = field.endianness.unwrap_or(default_endian);
        let size = field_size(&field.field_type);

        if current_offset + size > data.len() {
            return Err(TemplateError::InsufficientData {
                offset: current_offset,
                needed: size,
                available: data.len().saturating_sub(current_offset),
            });
        }

        let raw = data[current_offset..current_offset + size].to_vec();
        let display = format_field_value(&field.field_type, &raw, endian);

        let children = if let FieldType::Array(inner, count) = &field.field_type {
            let inner_size = field_size(inner);
            let mut arr_children = Vec::new();
            for i in 0..*count {
                let arr_offset = current_offset + i * inner_size;
                let arr_raw = data[arr_offset..arr_offset + inner_size].to_vec();
                let arr_display = format_field_value(inner, &arr_raw, endian);
                arr_children.push(ParsedField {
                    name: format!("[{}]", i),
                    offset: arr_offset,
                    size: inner_size,
                    raw_bytes: arr_raw,
                    display_value: arr_display,
                    children: Vec::new(),
                });
            }
            arr_children
        } else {
            Vec::new()
        };

        results.push(ParsedField {
            name: field.name.clone(),
            offset: current_offset,
            size,
            raw_bytes: raw,
            display_value: display,
            children,
        });

        current_offset += size;
    }

    Ok(results)
}

fn format_field_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> String {
    match ft {
        FieldType::UInt8 => format!("{} (0x{:02X})", raw[0], raw[0]),
        FieldType::Int8 => format!("{} (0x{:02X})", raw[0] as i8, raw[0]),
        FieldType::UInt16 => {
            let v = match endian {
                Endianness::Little => u16::from_le_bytes([raw[0], raw[1]]),
                Endianness::Big => u16::from_be_bytes([raw[0], raw[1]]),
            };
            format!("{} (0x{:04X})", v, v)
        }
        FieldType::Int16 => {
            let v = match endian {
                Endianness::Little => i16::from_le_bytes([raw[0], raw[1]]),
                Endianness::Big => i16::from_be_bytes([raw[0], raw[1]]),
            };
            format!("{} (0x{:04X})", v, v as u16)
        }
        FieldType::UInt32 => {
            let v = match endian {
                Endianness::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            format!("{} (0x{:08X})", v, v)
        }
        FieldType::Int32 => {
            let v = match endian {
                Endianness::Little => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            format!("{} (0x{:08X})", v, v as u32)
        }
        FieldType::UInt64 => {
            let v = match endian {
                Endianness::Little => u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
                Endianness::Big => u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
            };
            format!("{} (0x{:016X})", v, v)
        }
        FieldType::Int64 => {
            let v = match endian {
                Endianness::Little => i64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
                Endianness::Big => i64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
            };
            format!("{} (0x{:016X})", v, v as u64)
        }
        FieldType::Float32 => {
            let v = match endian {
                Endianness::Little => f32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            format!("{}", v)
        }
        FieldType::Float64 => {
            let v = match endian {
                Endianness::Little => f64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
                Endianness::Big => f64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]),
            };
            format!("{}", v)
        }
        FieldType::Bytes(n) => {
            let hex: Vec<String> = raw[..*n].iter().map(|b| format!("{:02X}", b)).collect();
            hex.join(" ")
        }
        FieldType::FixedString(n) => {
            let s: String = raw[..*n]
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("\"{}\"", s)
        }
        FieldType::Array(inner, count) => {
            format!("[{} x {}]", count, field_type_name(inner))
        }
    }
}

fn field_type_name(ft: &FieldType) -> &'static str {
    match ft {
        FieldType::UInt8 => "uint8",
        FieldType::Int8 => "int8",
        FieldType::UInt16 => "uint16",
        FieldType::Int16 => "int16",
        FieldType::UInt32 => "uint32",
        FieldType::Int32 => "int32",
        FieldType::UInt64 => "uint64",
        FieldType::Int64 => "int64",
        FieldType::Float32 => "float32",
        FieldType::Float64 => "float64",
        FieldType::Bytes(_) => "bytes",
        FieldType::FixedString(_) => "string",
        FieldType::Array(_, _) => "array",
    }
}

fn register_builtins(registry: &mut TemplateRegistry) {
    pe::register_templates(registry);
    elf::register_templates(registry);
    macho::register_templates(registry);
    zip::register_templates(registry);
    common::register_templates(registry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_builtins() {
        let reg = TemplateRegistry::new();
        let list = reg.list();
        assert!(!list.is_empty());
        assert!(list.iter().any(|(name, _)| name == "IMAGE_DOS_HEADER"));
    }

    #[test]
    fn test_apply_nonexistent() {
        let reg = TemplateRegistry::new();
        let result = reg.apply("NONEXISTENT", &[0u8; 100], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_dos_header() {
        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;

        let reg = TemplateRegistry::new();
        let fields = reg.apply("IMAGE_DOS_HEADER", &data, 0).unwrap();
        assert!(!fields.is_empty());
        assert_eq!(fields[0].name, "e_magic");
        assert!(fields[0].display_value.contains("23117") || fields[0].display_value.contains("5A4D"));
    }

    #[test]
    fn test_insufficient_data() {
        let reg = TemplateRegistry::new();
        let result = reg.apply("IMAGE_DOS_HEADER", &[0u8; 10], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_template() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "TEST".to_string(),
            description: "Test template".to_string(),
            default_endianness: Endianness::Little,
            fields: vec![
                FieldDefinition {
                    name: "magic".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: "Magic number".to_string(),
                },
                FieldDefinition {
                    name: "version".to_string(),
                    field_type: FieldType::UInt8,
                    endianness: None,
                    description: "Version".to_string(),
                },
            ],
        });

        let data = [0x42, 0x4D, 0x03];
        let fields = reg.apply("TEST", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "magic");
        assert_eq!(fields[1].name, "version");
    }
}
