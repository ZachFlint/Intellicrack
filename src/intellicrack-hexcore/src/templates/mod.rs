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
        assert!(matches!(result, Err(TemplateError::NotFound(n)) if n == "NONEXISTENT"));
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
        assert_eq!(fields[0].display_value, "23117 (0x5A4D)");
    }

    #[test]
    fn test_insufficient_data() {
        let reg = TemplateRegistry::new();
        let result = reg.apply("IMAGE_DOS_HEADER", &[0u8; 10], 0);
        assert!(matches!(result, Err(TemplateError::InsufficientData { .. })));
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
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"].as_str(), Some("IMAGE_DOS_HEADER"));
        assert_eq!(parsed["fields"][0]["name"].as_str(), Some("e_magic"));
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

    #[test]
    fn test_format_field_value_integers_little_endian() {
        assert_eq!(format_field_value(&FieldType::UInt8, &[0x2A], Endianness::Little), "42 (0x2A)");
        assert_eq!(format_field_value(&FieldType::Int8, &[0xFF], Endianness::Little), "-1 (0xFF)");
        assert_eq!(format_field_value(&FieldType::Bool, &[0x01], Endianness::Little), "true");
        assert_eq!(format_field_value(&FieldType::Bool, &[0x00], Endianness::Little), "false");
        assert_eq!(format_field_value(&FieldType::Char, &[0x41], Endianness::Little), "'A' (0x41)");
        assert_eq!(format_field_value(&FieldType::Char, &[0x01], Endianness::Little), "0x01");
        assert_eq!(
            format_field_value(&FieldType::UInt16, &[0x34, 0x12], Endianness::Little),
            "4660 (0x1234)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Little),
            "-1 (0xFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt32, &[0x78, 0x56, 0x34, 0x12], Endianness::Little),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int32, &[0xFF, 0xFF, 0xFF, 0xFF], Endianness::Little),
            "-1 (0xFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt64, &[1, 0, 0, 0, 0, 0, 0, 0], Endianness::Little),
            "1 (0x0000000000000001)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int64, &[0xFF; 8], Endianness::Little),
            "-1 (0xFFFFFFFFFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::Float32, &1.5f32.to_le_bytes(), Endianness::Little),
            "1.5"
        );
        assert_eq!(
            format_field_value(&FieldType::Float64, &2.5f64.to_le_bytes(), Endianness::Little),
            "2.5"
        );
    }

    #[test]
    fn test_format_field_value_integers_big_endian() {
        assert_eq!(
            format_field_value(&FieldType::UInt16, &[0x12, 0x34], Endianness::Big),
            "4660 (0x1234)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Big),
            "-1 (0xFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt32, &[0x12, 0x34, 0x56, 0x78], Endianness::Big),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int32, &[0xFF, 0xFF, 0xFF, 0xFF], Endianness::Big),
            "-1 (0xFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt64, &[0, 0, 0, 0, 0, 0, 0, 1], Endianness::Big),
            "1 (0x0000000000000001)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int64, &[0xFF; 8], Endianness::Big),
            "-1 (0xFFFFFFFFFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::Float32, &1.5f32.to_be_bytes(), Endianness::Big),
            "1.5"
        );
        assert_eq!(
            format_field_value(&FieldType::Float64, &2.5f64.to_be_bytes(), Endianness::Big),
            "2.5"
        );
    }

    #[test]
    fn test_format_composite_value_all_variants() {
        assert_eq!(
            format_field_value(&FieldType::Bytes(3), &[0xAA, 0xBB, 0xCC], Endianness::Little),
            "AA BB CC"
        );
        // Null-truncation + non-graphic byte -> '.'.
        assert_eq!(
            format_field_value(&FieldType::FixedString(4), &[0x41, 0x01, 0x42, 0x00], Endianness::Little),
            "\"A.B\""
        );
        assert_eq!(
            format_field_value(
                &FieldType::Array { element_type: Box::new(FieldType::UInt8), count: 4 },
                &[],
                Endianness::Little
            ),
            "[4 x uint8]"
        );
        assert_eq!(
            format_field_value(&FieldType::Padding(8), &[], Endianness::Little),
            "padding[8]"
        );
        assert_eq!(
            format_field_value(
                &FieldType::DynamicArray { element_type: Box::new(FieldType::UInt8), count_field: "count".to_string() },
                &[],
                Endianness::Little
            ),
            "[dyn count x uint8]"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Bitfield { bit_width: 3, backing_type: Box::new(FieldType::UInt8), flags: None },
                &[],
                Endianness::Little
            ),
            "bitfield<uint8:3>"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Union {
                    variants: vec![
                        FieldDefinition {
                            name: "a".to_string(),
                            field_type: FieldType::UInt8,
                            endianness: None,
                            description: String::new(),
                            color: None,
                            validation: None,
                        },
                        FieldDefinition {
                            name: "b".to_string(),
                            field_type: FieldType::UInt16,
                            endianness: None,
                            description: String::new(),
                            color: None,
                            validation: None,
                        },
                    ],
                },
                &[],
                Endianness::Little
            ),
            "union<2 variants>"
        );
    }

    #[test]
    fn test_format_composite_value_reference_variants() {
        assert_eq!(
            format_field_value(
                &FieldType::Enum { backing_type: Box::new(FieldType::UInt16), values: vec![] },
                &[],
                Endianness::Little
            ),
            "enum<uint16>"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Pointer { pointer_type: Box::new(FieldType::UInt32), target_template: "FOO".to_string() },
                &[],
                Endianness::Little
            ),
            "*FOO"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Conditional {
                    condition_field: "flag".to_string(),
                    condition_value: 1,
                    condition_op: ConditionOp::Eq,
                    fields: vec![],
                },
                &[],
                Endianness::Little
            ),
            "if(flag)"
        );
        assert_eq!(
            format_field_value(&FieldType::StructRef("BAR".to_string()), &[], Endianness::Little),
            "struct BAR"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Computed { expression: "a+b".to_string(), display_type: Box::new(FieldType::UInt32) },
                &[],
                Endianness::Little
            ),
            "= a+b"
        );
        assert_eq!(
            format_field_value(
                &FieldType::EndiannessSwitch { peek_offset: 4, big_value: 0xAB },
                &[],
                Endianness::Little
            ),
            "endianness_switch(peek+4==0xAB)"
        );
    }

    #[test]
    fn test_read_numeric_value_all_types_both_endian() {
        assert_eq!(read_numeric_value(&FieldType::UInt8, &[0x2A], Endianness::Little), 42);
        assert_eq!(read_numeric_value(&FieldType::Bool, &[0x01], Endianness::Little), 1);
        assert_eq!(read_numeric_value(&FieldType::Char, &[0x41], Endianness::Little), 65);
        assert_eq!(read_numeric_value(&FieldType::Int8, &[0xFF], Endianness::Little), -1);
        assert_eq!(read_numeric_value(&FieldType::UInt16, &[0x34, 0x12], Endianness::Little), 4660);
        assert_eq!(read_numeric_value(&FieldType::UInt16, &[0x12, 0x34], Endianness::Big), 4660);
        assert_eq!(read_numeric_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Little), -1);
        assert_eq!(read_numeric_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Big), -1);
        assert_eq!(
            read_numeric_value(&FieldType::UInt32, &[0x78, 0x56, 0x34, 0x12], Endianness::Little),
            0x1234_5678
        );
        assert_eq!(
            read_numeric_value(&FieldType::UInt32, &[0x12, 0x34, 0x56, 0x78], Endianness::Big),
            0x1234_5678
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int32, &[0xFF, 0xFF, 0xFF, 0xFF], Endianness::Little),
            -1
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int32, &[0xFF, 0xFF, 0xFF, 0xFF], Endianness::Big),
            -1
        );
        assert_eq!(
            read_numeric_value(&FieldType::UInt64, &[1, 0, 0, 0, 0, 0, 0, 0], Endianness::Little),
            1
        );
        assert_eq!(
            read_numeric_value(&FieldType::UInt64, &[0, 0, 0, 0, 0, 0, 0, 1], Endianness::Big),
            1
        );
        assert_eq!(read_numeric_value(&FieldType::Int64, &[0xFF; 8], Endianness::Little), -1);
        assert_eq!(read_numeric_value(&FieldType::Int64, &[0xFF; 8], Endianness::Big), -1);
        // Non-numeric (float/composite) types fall through to 0.
        assert_eq!(read_numeric_value(&FieldType::Float32, &[0; 4], Endianness::Little), 0);
        assert_eq!(read_numeric_value(&FieldType::Bytes(2), &[0; 2], Endianness::Little), 0);
    }

    #[test]
    fn test_field_type_name_every_variant() {
        assert_eq!(field_type_name(&FieldType::UInt8), "uint8");
        assert_eq!(field_type_name(&FieldType::Int8), "int8");
        assert_eq!(field_type_name(&FieldType::UInt16), "uint16");
        assert_eq!(field_type_name(&FieldType::Int16), "int16");
        assert_eq!(field_type_name(&FieldType::UInt32), "uint32");
        assert_eq!(field_type_name(&FieldType::Int32), "int32");
        assert_eq!(field_type_name(&FieldType::UInt64), "uint64");
        assert_eq!(field_type_name(&FieldType::Int64), "int64");
        assert_eq!(field_type_name(&FieldType::Float32), "float32");
        assert_eq!(field_type_name(&FieldType::Float64), "float64");
        assert_eq!(field_type_name(&FieldType::Bytes(1)), "bytes");
        assert_eq!(field_type_name(&FieldType::FixedString(1)), "string");
        assert_eq!(field_type_name(&FieldType::Array { element_type: Box::new(FieldType::UInt8), count: 1 }), "array");
        assert_eq!(field_type_name(&FieldType::Bool), "bool");
        assert_eq!(field_type_name(&FieldType::Char), "char");
        assert_eq!(field_type_name(&FieldType::Padding(1)), "padding");
    }

    #[test]
    fn test_field_type_name_composite_variants() {
        assert_eq!(
            field_type_name(&FieldType::DynamicArray { element_type: Box::new(FieldType::UInt8), count_field: "c".to_string() }),
            "dynamic_array"
        );
        assert_eq!(
            field_type_name(&FieldType::Bitfield { bit_width: 1, backing_type: Box::new(FieldType::UInt8), flags: None }),
            "bitfield"
        );
        assert_eq!(field_type_name(&FieldType::Union { variants: vec![] }), "union");
        assert_eq!(
            field_type_name(&FieldType::Enum { backing_type: Box::new(FieldType::UInt8), values: vec![] }),
            "enum"
        );
        assert_eq!(
            field_type_name(&FieldType::Pointer { pointer_type: Box::new(FieldType::UInt8), target_template: "t".to_string() }),
            "pointer"
        );
        assert_eq!(
            field_type_name(&FieldType::Conditional {
                condition_field: "f".to_string(),
                condition_value: 0,
                condition_op: ConditionOp::Eq,
                fields: vec![],
            }),
            "conditional"
        );
        assert_eq!(field_type_name(&FieldType::StructRef("s".to_string())), "struct_ref");
        assert_eq!(
            field_type_name(&FieldType::Computed { expression: "e".to_string(), display_type: Box::new(FieldType::UInt8) }),
            "computed"
        );
        assert_eq!(
            field_type_name(&FieldType::EndiannessSwitch { peek_offset: 0, big_value: 0 }),
            "endianness_switch"
        );
    }

    #[test]
    fn test_export_json_not_found() {
        let reg = TemplateRegistry::new();
        let err = reg.export_json("NO_SUCH_TEMPLATE").unwrap_err();
        assert!(
            matches!(&err, TemplateError::NotFound(n) if n == "NO_SUCH_TEMPLATE"),
            "got {err:?}"
        );
    }
}
