pub mod common;
pub mod elf;
pub mod eval;
pub mod json_schema;
pub mod macho;
pub mod pe;
pub mod zip;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    BitAnd,
    BitAndZero,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValidation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicDetection {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
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
    Array {
        element_type: Box<FieldType>,
        count: usize,
    },
    Bool,
    Char,
    Padding(usize),
    DynamicArray {
        element_type: Box<FieldType>,
        count_field: String,
    },
    Bitfield {
        bit_width: u8,
        backing_type: Box<FieldType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flags: Option<Vec<(String, u64)>>,
    },
    Union {
        variants: Vec<FieldDefinition>,
    },
    Enum {
        backing_type: Box<FieldType>,
        values: Vec<(String, i64)>,
    },
    Pointer {
        pointer_type: Box<FieldType>,
        target_template: String,
    },
    Conditional {
        condition_field: String,
        condition_value: i64,
        condition_op: ConditionOp,
        fields: Vec<FieldDefinition>,
    },
    StructRef(String),
    Computed {
        expression: String,
        display_type: Box<FieldType>,
    },
    EndiannessSwitch {
        peek_offset: usize,
        big_value: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub name: String,
    pub field_type: FieldType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<FieldValidation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructTemplate {
    pub name: String,
    pub description: String,
    pub fields: Vec<FieldDefinition>,
    pub default_endianness: Endianness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_detection: Option<MagicDetection>,
}

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub raw_bytes: Vec<u8>,
    pub display_value: String,
    pub children: Vec<ParsedField>,
    pub color: Option<String>,
    pub validation_passed: Option<bool>,
    pub description: String,
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
    #[error("JSON parse error: {0}")]
    JsonParse(String),
    #[error("invalid field reference: {0}")]
    InvalidFieldReference(String),
    #[error("expression error: {0}")]
    ExpressionError(String),
    #[error("circular reference: {0}")]
    CircularReference(String),
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("unknown type in sizeof(): {0}")]
    UnknownType(String),
}

pub struct TemplateRegistry {
    templates: HashMap<String, StructTemplate>,
}

impl TemplateRegistry {
    #[must_use]
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

    /// Register a template from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `TemplateError::JsonParse` if the JSON is invalid or
    /// `TemplateError::InvalidFieldReference` if field references are invalid.
    pub fn register_json(&mut self, json_str: &str) -> Result<String, TemplateError> {
        let template = json_schema::parse_json_template(json_str)?;
        let name = template.name.clone();
        self.templates.insert(name.clone(), template);
        Ok(name)
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.templates.remove(name).is_some()
    }

    /// Export a template to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `TemplateError::NotFound` if the template does not exist or
    /// `TemplateError::JsonParse` if serialization fails.
    pub fn export_json(&self, name: &str) -> Result<String, TemplateError> {
        let template = self
            .templates
            .get(name)
            .ok_or_else(|| TemplateError::NotFound(name.to_string()))?;
        json_schema::template_to_json(template)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&StructTemplate> {
        self.templates.get(name)
    }

    #[must_use]
    pub fn list(&self) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = self
            .templates
            .iter()
            .map(|(k, v)| (k.clone(), v.description.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    #[must_use]
    pub fn list_detailed(&self) -> Vec<(String, String, String, usize)> {
        let mut entries: Vec<(String, String, String, usize)> = self
            .templates
            .iter()
            .map(|(k, v)| {
                let category = v.category.clone().unwrap_or_default();
                (k.clone(), v.description.clone(), category, v.fields.len())
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Apply a named template to binary data at the given offset.
    ///
    /// # Errors
    ///
    /// Returns `TemplateError::NotFound` if the template does not exist,
    /// `TemplateError::InsufficientData` if there is not enough data, or
    /// other `TemplateError` variants for evaluation failures.
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

        let mut evaluator =
            eval::TemplateEvaluator::new(data, offset, template.default_endianness, self);
        evaluator.evaluate_fields(&template.fields)
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn field_size(ft: &FieldType) -> usize {
    match ft {
        FieldType::UInt8 | FieldType::Int8 | FieldType::Bool | FieldType::Char => 1,
        FieldType::UInt16 | FieldType::Int16 => 2,
        FieldType::UInt32 | FieldType::Int32 | FieldType::Float32 => 4,
        FieldType::UInt64 | FieldType::Int64 | FieldType::Float64 => 8,
        FieldType::Bytes(n) | FieldType::FixedString(n) | FieldType::Padding(n) => *n,
        FieldType::Array {
            element_type,
            count,
        } => field_size(element_type) * count,
        FieldType::Bitfield { backing_type, .. } | FieldType::Enum { backing_type, .. } => {
            field_size(backing_type)
        }
        FieldType::Pointer { pointer_type, .. } => field_size(pointer_type),
        FieldType::DynamicArray { .. }
        | FieldType::Union { .. }
        | FieldType::Conditional { .. }
        | FieldType::StructRef(_)
        | FieldType::Computed { .. }
        | FieldType::EndiannessSwitch { .. } => 0,
    }
}

fn format_integer_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> String {
    match ft {
        FieldType::UInt8 => format!("{} (0x{:02X})", raw[0], raw[0]),
        FieldType::Int8 => {
            let signed = i8::from_ne_bytes([raw[0]]);
            format!("{signed} (0x{:02X})", raw[0])
        }
        FieldType::Bool => {
            if raw[0] != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        FieldType::Char => {
            let ch = raw[0];
            if ch.is_ascii_graphic() || ch == b' ' {
                format!("'{}' (0x{ch:02X})", ch as char)
            } else {
                format!("0x{ch:02X}")
            }
        }
        FieldType::UInt16 => {
            let v = match endian {
                Endianness::Little => u16::from_le_bytes([raw[0], raw[1]]),
                Endianness::Big => u16::from_be_bytes([raw[0], raw[1]]),
            };
            format!("{v} (0x{v:04X})")
        }
        FieldType::Int16 => {
            let v = match endian {
                Endianness::Little => i16::from_le_bytes([raw[0], raw[1]]),
                Endianness::Big => i16::from_be_bytes([raw[0], raw[1]]),
            };
            let u = u16::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:04X})")
        }
        FieldType::UInt32 => {
            let v = match endian {
                Endianness::Little => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            format!("{v} (0x{v:08X})")
        }
        FieldType::Int32 => {
            let v = match endian {
                Endianness::Little => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            let u = u32::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:08X})")
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
            format!("{v} (0x{v:016X})")
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
            let u = u64::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:016X})")
        }
        FieldType::Float32 => {
            let v = match endian {
                Endianness::Little => f32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                Endianness::Big => f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            };
            format!("{v}")
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
            format!("{v}")
        }
        _ => String::new(),
    }
}

fn format_composite_value(ft: &FieldType, raw: &[u8]) -> String {
    match ft {
        FieldType::Bytes(n) => {
            let hex: Vec<String> = raw[..*n].iter().map(|b| format!("{b:02X}")).collect();
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
            format!("\"{s}\"")
        }
        FieldType::Array {
            element_type,
            count,
        } => {
            format!("[{count} x {}]", field_type_name(element_type))
        }
        FieldType::Padding(n) => format!("padding[{n}]"),
        FieldType::DynamicArray {
            element_type,
            count_field,
        } => format!("[dyn {count_field} x {}]", field_type_name(element_type)),
        FieldType::Bitfield {
            bit_width,
            backing_type,
            ..
        } => format!("bitfield<{}:{bit_width}>", field_type_name(backing_type)),
        FieldType::Union { variants } => format!("union<{} variants>", variants.len()),
        FieldType::Enum { backing_type, .. } => {
            format!("enum<{}>", field_type_name(backing_type))
        }
        FieldType::Pointer {
            target_template, ..
        } => format!("*{target_template}"),
        FieldType::Conditional {
            condition_field, ..
        } => {
            format!("if({condition_field})")
        }
        FieldType::StructRef(name) => format!("struct {name}"),
        FieldType::Computed { expression, .. } => format!("= {expression}"),
        FieldType::EndiannessSwitch {
            peek_offset,
            big_value,
        } => format!("endianness_switch(peek+{peek_offset}=={big_value:#04X})"),
        _ => String::new(),
    }
}

#[must_use]
pub fn format_field_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> String {
    match ft {
        FieldType::UInt8
        | FieldType::Int8
        | FieldType::Bool
        | FieldType::Char
        | FieldType::UInt16
        | FieldType::Int16
        | FieldType::UInt32
        | FieldType::Int32
        | FieldType::UInt64
        | FieldType::Int64
        | FieldType::Float32
        | FieldType::Float64 => format_integer_value(ft, raw, endian),
        _ => format_composite_value(ft, raw),
    }
}

#[must_use]
pub fn field_type_name(ft: &FieldType) -> &'static str {
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
        FieldType::Array { .. } => "array",
        FieldType::Bool => "bool",
        FieldType::Char => "char",
        FieldType::Padding(_) => "padding",
        FieldType::DynamicArray { .. } => "dynamic_array",
        FieldType::Bitfield { .. } => "bitfield",
        FieldType::Union { .. } => "union",
        FieldType::Enum { .. } => "enum",
        FieldType::Pointer { .. } => "pointer",
        FieldType::Conditional { .. } => "conditional",
        FieldType::StructRef(_) => "struct_ref",
        FieldType::Computed { .. } => "computed",
        FieldType::EndiannessSwitch { .. } => "endianness_switch",
    }
}

#[must_use]
pub fn read_numeric_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> i64 {
    match ft {
        FieldType::UInt8 | FieldType::Bool | FieldType::Char => i64::from(raw[0]),
        FieldType::Int8 => i64::from(i8::from_ne_bytes([raw[0]])),
        FieldType::UInt16 => match endian {
            Endianness::Little => i64::from(u16::from_le_bytes([raw[0], raw[1]])),
            Endianness::Big => i64::from(u16::from_be_bytes([raw[0], raw[1]])),
        },
        FieldType::Int16 => match endian {
            Endianness::Little => i64::from(i16::from_le_bytes([raw[0], raw[1]])),
            Endianness::Big => i64::from(i16::from_be_bytes([raw[0], raw[1]])),
        },
        FieldType::UInt32 => match endian {
            Endianness::Little => i64::from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
            Endianness::Big => i64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])),
        },
        FieldType::Int32 => match endian {
            Endianness::Little => i64::from(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
            Endianness::Big => i64::from(i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])),
        },
        FieldType::UInt64 => match endian {
            Endianness::Little => i64::from_ne_bytes(
                u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ])
                .to_ne_bytes(),
            ),
            Endianness::Big => i64::from_ne_bytes(
                u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ])
                .to_ne_bytes(),
            ),
        },
        FieldType::Int64 => match endian {
            Endianness::Little => i64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]),
            Endianness::Big => i64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]),
        },
        _ => 0,
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
        assert!(
            fields[0].display_value.contains("23117") || fields[0].display_value.contains("5A4D")
        );
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
            version: None,
            author: None,
            category: None,
            magic_detection: None,
            fields: vec![
                FieldDefinition {
                    name: "magic".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: "Magic number".to_string(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    name: "version".to_string(),
                    field_type: FieldType::UInt8,
                    endianness: None,
                    description: "Version".to_string(),
                    color: None,
                    validation: None,
                },
            ],
        });

        let data = [0x42, 0x4D, 0x03];
        let fields = reg.apply("TEST", &data, 0).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "magic");
        assert_eq!(fields[1].name, "version");
    }

    #[test]
    fn test_register_json() {
        let mut reg = TemplateRegistry::new();
        let json = r#"{
            "name": "JSON_TEST",
            "description": "Test from JSON",
            "default_endianness": "little",
            "fields": [
                {
                    "name": "magic",
                    "field_type": {"type": "UInt16"},
                    "description": "Magic"
                }
            ]
        }"#;
        let name = reg.register_json(json).unwrap();
        assert_eq!(name, "JSON_TEST");
        assert!(reg.get("JSON_TEST").is_some());
    }

    #[test]
    fn test_export_json() {
        let reg = TemplateRegistry::new();
        let json = reg.export_json("IMAGE_DOS_HEADER").unwrap();
        assert!(json.contains("IMAGE_DOS_HEADER"));
        assert!(json.contains("e_magic"));
    }

    #[test]
    fn test_json_roundtrip() {
        let reg = TemplateRegistry::new();
        let json = reg.export_json("IMAGE_DOS_HEADER").unwrap();
        let mut reg2 = TemplateRegistry::new();
        let name = reg2.register_json(&json).unwrap();
        assert_eq!(name, "IMAGE_DOS_HEADER");

        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        let fields1 = reg.apply("IMAGE_DOS_HEADER", &data, 0).unwrap();
        let fields2 = reg2.apply("IMAGE_DOS_HEADER", &data, 0).unwrap();
        assert_eq!(fields1.len(), fields2.len());
        for (f1, f2) in fields1.iter().zip(fields2.iter()) {
            assert_eq!(f1.name, f2.name);
            assert_eq!(f1.display_value, f2.display_value);
        }
    }

    #[test]
    fn test_remove() {
        let mut reg = TemplateRegistry::new();
        assert!(reg.get("IMAGE_DOS_HEADER").is_some());
        assert!(reg.remove("IMAGE_DOS_HEADER"));
        assert!(reg.get("IMAGE_DOS_HEADER").is_none());
        assert!(!reg.remove("NONEXISTENT"));
    }

    #[test]
    fn test_list_detailed() {
        let reg = TemplateRegistry::new();
        let detailed = reg.list_detailed();
        assert!(!detailed.is_empty());
        let dos = detailed
            .iter()
            .find(|(name, _, _, _)| name == "IMAGE_DOS_HEADER")
            .expect("IMAGE_DOS_HEADER must appear in list_detailed");
        // IMAGE_DOS_HEADER per WinNT.h has exactly 19 named members:
        // e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,
        // e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res[4], e_oemid, e_oeminfo, e_res2[10],
        // e_lfanew.  Deleting any field registration changes this count and fails the gate.
        assert_eq!(dos.3, 19, "IMAGE_DOS_HEADER must expose exactly 19 fields in list_detailed");
    }
}
