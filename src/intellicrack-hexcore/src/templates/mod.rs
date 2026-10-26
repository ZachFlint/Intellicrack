// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Structure templates: named layouts of typed fields that are evaluated
//! against a document at an offset to produce parsed fields, plus the registry
//! of built-in templates for PE, ELF, Mach-O, ZIP and common structures and of
//! templates registered from JSON.

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

/// Byte order of a multi-byte field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

/// How a [`FieldType::Conditional`] compares an earlier field's value with
/// its `condition_value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOp {
    /// The value equals the condition value.
    Eq,
    /// The value differs from the condition value.
    Ne,
    /// The value is greater than the condition value.
    Gt,
    /// The value is less than the condition value.
    Lt,
    /// The value is at least the condition value.
    Ge,
    /// The value is at most the condition value.
    Le,
    /// The value has at least one of the condition value's bits set.
    BitAnd,
    /// The value has none of the condition value's bits set.
    BitAndZero,
}

/// Checks a parsed field must pass for its `validation_passed` to be true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValidation {
    /// The exact value the field must hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<i64>,
    /// The smallest value the field may hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_value: Option<i64>,
    /// The largest value the field may hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<i64>,
    /// Bytes the field's raw bytes must start with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_bytes: Option<Vec<u8>>,
}

/// The signature that identifies a structure: `bytes` found at `offset` past
/// its start; see [`TemplateRegistry::detect`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicDetection {
    /// Where the signature starts, relative to the structure's start.
    pub offset: usize,
    /// The signature itself.
    pub bytes: Vec<u8>,
}

/// What a field is and how its bytes are read and shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
pub enum FieldType {
    /// Unsigned 8-bit integer.
    UInt8,
    /// Signed 8-bit integer.
    Int8,
    /// Unsigned 16-bit integer.
    UInt16,
    /// Signed 16-bit integer.
    Int16,
    /// Unsigned 32-bit integer.
    UInt32,
    /// Signed 32-bit integer.
    Int32,
    /// Unsigned 64-bit integer.
    UInt64,
    /// Signed 64-bit integer.
    Int64,
    /// IEEE 754 single-precision float.
    Float32,
    /// IEEE 754 double-precision float.
    Float64,
    /// This many raw bytes, shown as hex.
    Bytes(usize),
    /// Text of this many bytes, shown up to its first NUL.
    FixedString(usize),
    /// `count` consecutive elements of one type.
    Array {
        /// Type of every element.
        element_type: Box<FieldType>,
        /// How many elements there are.
        count: usize,
    },
    /// One byte, false when zero.
    Bool,
    /// One byte shown as a character.
    Char,
    /// This many bytes skipped over.
    Padding(usize),
    /// An array whose element count is the value of an earlier field.
    DynamicArray {
        /// Type of every element.
        element_type: Box<FieldType>,
        /// Name of the earlier field holding the count.
        count_field: String,
    },
    /// The low `bit_width` bits of an integer, optionally broken into named
    /// flags.
    Bitfield {
        /// How many low bits of the backing integer the field keeps.
        bit_width: u8,
        /// Integer type the bits are read from.
        backing_type: Box<FieldType>,
        /// `(name, mask)` pairs, each shown as set or clear.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flags: Option<Vec<(String, u64)>>,
    },
    /// Alternative layouts of the same bytes, each evaluated from the same
    /// start; the field is as long as the longest.
    Union {
        /// The alternative layouts.
        variants: Vec<FieldDefinition>,
    },
    /// An integer shown with the name its value has.
    Enum {
        /// Integer type the value is read from.
        backing_type: Box<FieldType>,
        /// `(name, value)` pairs.
        values: Vec<(String, i64)>,
    },
    /// An integer offset, relative to the structure's base, at which another
    /// template is evaluated.
    Pointer {
        /// Integer type the offset is read from.
        pointer_type: Box<FieldType>,
        /// Name of the template evaluated at the offset.
        target_template: String,
    },
    /// Fields that are present only when an earlier field's value meets a
    /// condition.
    Conditional {
        /// Name of the earlier field tested.
        condition_field: String,
        /// The value it is compared with.
        condition_value: i64,
        /// How the two are compared.
        condition_op: ConditionOp,
        /// The fields present when the condition holds.
        fields: Vec<FieldDefinition>,
    },
    /// Another registered template, evaluated in place as a nested structure.
    StructRef(String),
    /// A value computed from an expression over earlier fields, taking no
    /// bytes.
    Computed {
        /// The expression, which may name earlier fields, `$` and `sizeof()`.
        expression: String,
        /// The type the value is described as.
        display_type: Box<FieldType>,
    },
    /// Takes no bytes; sets the byte order of the fields that follow from one
    /// byte of the structure, as an ELF header's `EI_DATA` does.
    EndiannessSwitch {
        /// Offset of the byte, relative to the structure's base.
        peek_offset: usize,
        /// The byte value that means big-endian; any other means little.
        big_value: u8,
    },
}

/// One named field of a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// The field's name, which later fields' expressions can refer to.
    pub name: String,
    /// What the field is.
    pub field_type: FieldType,
    /// Byte order for this field, overriding the template's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Display color for the field's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Checks the parsed value must pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<FieldValidation>,
    /// An expression giving the field's position relative to the structure's
    /// base, instead of directly after the previous field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// A named structure layout: an ordered list of fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructTemplate {
    /// The name the template is registered and applied under.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The fields, in order.
    pub fields: Vec<FieldDefinition>,
    /// Byte order of fields that set none of their own.
    pub default_endianness: Endianness,
    /// Version of the template's definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Who wrote the template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Grouping shown in template lists, such as `PE` or `ZIP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The signature that identifies the structure, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_detection: Option<MagicDetection>,
}

/// One field as parsed from data by a template.
#[derive(Debug, Clone)]
pub struct ParsedField {
    /// The field's name.
    pub name: String,
    /// Absolute offset of the field's first byte.
    pub offset: usize,
    /// How many bytes the field covers.
    pub size: usize,
    /// The field's bytes.
    pub raw_bytes: Vec<u8>,
    /// The value as shown to the user.
    pub display_value: String,
    /// Nested fields: array elements, flags, struct members.
    pub children: Vec<ParsedField>,
    /// Display color for the field's bytes.
    pub color: Option<String>,
    /// Whether the value passed the field's validation, when it has one.
    pub validation_passed: Option<bool>,
    /// Human-readable description.
    pub description: String,
}

/// Errors raised while registering, sizing or applying a template.
#[derive(Error, Debug)]
pub enum TemplateError {
    /// No template is registered under the name.
    #[error("template not found: {0}")]
    NotFound(String),
    /// The data ends before a field does.
    #[error("insufficient data at offset {offset}: need {needed} bytes, have {available}")]
    InsufficientData {
        /// Where the field starts.
        offset: usize,
        /// Bytes the field needs.
        needed: usize,
        /// Bytes left from `offset`.
        available: usize,
    },
    /// A JSON template is malformed.
    #[error("JSON parse error: {0}")]
    JsonParse(String),
    /// A field refers to a field, template or expression that is invalid.
    #[error("invalid field reference: {0}")]
    InvalidFieldReference(String),
    /// An expression could not be parsed or evaluated.
    #[error("expression error: {0}")]
    ExpressionError(String),
    /// Templates refer to each other more deeply than evaluation allows.
    #[error("circular reference: {0}")]
    CircularReference(String),
    /// A value failed its validation.
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    /// `sizeof()` named something that is not a type or template.
    #[error("unknown type in sizeof(): {0}")]
    UnknownType(String),
    /// A field type's size depends on the data, where a fixed size is needed.
    #[error("field type has no statically known size: {0}")]
    UnsizedFieldType(String),
    /// Evaluation exceeded its field-count or output-size budget.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
}

/// A named collection of struct templates, seeded with the built-ins and
/// extensible at runtime with user templates parsed from JSON.
pub struct TemplateRegistry {
    templates: HashMap<String, StructTemplate>,
}

impl TemplateRegistry {
    /// A registry holding every built-in template.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            templates: HashMap::new(),
        };
        register_builtins(&mut registry);
        registry
    }

    /// Inserts a template under its own name, replacing any template already
    /// registered under that name.
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

    /// Removes the template registered under `name`, returning whether one
    /// was present.
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

    /// The template registered under `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&StructTemplate> {
        self.templates.get(name)
    }

    /// Names of the templates whose declared magic matches `data`, read as
    /// starting where the structure would start, in name order.
    ///
    /// A template matches when it declares a non-empty magic and `data` holds
    /// exactly those bytes at the magic's offset; a template without a magic
    /// is never reported, and neither is one whose magic runs past `data`.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<String> {
        let mut names: Vec<String> = self
            .templates
            .values()
            .filter(|template| {
                template.magic_detection.as_ref().is_some_and(|magic| {
                    !magic.bytes.is_empty()
                        && data.get(magic.offset..magic.offset.saturating_add(magic.bytes.len()))
                            == Some(magic.bytes.as_slice())
                })
            })
            .map(|template| template.name.clone())
            .collect();
        names.sort();
        names
    }

    /// How many bytes past a structure's start the farthest-reaching magic of
    /// any registered template ends, which is all [`TemplateRegistry::detect`]
    /// needs to see.
    #[must_use]
    pub fn magic_extent(&self) -> usize {
        self.templates
            .values()
            .filter_map(|template| template.magic_detection.as_ref())
            .map(|magic| magic.offset.saturating_add(magic.bytes.len()))
            .max()
            .unwrap_or(0)
    }

    /// Every template's `(name, description)`, in name order.
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

    /// Every template's `(name, description, category, field count)`, in name
    /// order, with an empty category for a template that declares none.
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

/// Compute the static byte size of a `FieldType`, when one exists.
///
/// Returns `None` for `FieldType` variants whose size can only be known by
/// evaluating them against binary data (`DynamicArray`, `Union`,
/// `Conditional`, `StructRef`, `Computed`, `EndiannessSwitch`) — these are
/// dispatched to dedicated handlers in `eval.rs` that compute their own real
/// sizes and must never be sized via a flat multiplication or added to a
/// running struct offset. `Array`'s size is `None` whenever its element type
/// is itself unsized, or when `element_size * count` would overflow `usize`
/// (checked via `checked_mul` rather than a plain `*`).
///
/// `Some(0)` is a distinct, legitimate outcome (e.g. `Bytes(0)`,
/// `Padding(0)`, `FixedString(0)`, or an `Array` of such zero-length
/// elements) and must never be conflated with the "cannot be sized" case.
#[must_use]
pub fn field_size(ft: &FieldType) -> Option<usize> {
    match ft {
        FieldType::UInt8 | FieldType::Int8 | FieldType::Bool | FieldType::Char => Some(1),
        FieldType::UInt16 | FieldType::Int16 => Some(2),
        FieldType::UInt32 | FieldType::Int32 | FieldType::Float32 => Some(4),
        FieldType::UInt64 | FieldType::Int64 | FieldType::Float64 => Some(8),
        FieldType::Bytes(n) | FieldType::FixedString(n) | FieldType::Padding(n) => Some(*n),
        FieldType::Array {
            element_type,
            count,
        } => field_size(element_type).and_then(|elem_size| elem_size.checked_mul(*count)),
        FieldType::Bitfield { backing_type, .. } | FieldType::Enum { backing_type, .. } => {
            field_size(backing_type)
        }
        FieldType::Pointer { pointer_type, .. } => field_size(pointer_type),
        FieldType::DynamicArray { .. }
        | FieldType::Union { .. }
        | FieldType::Conditional { .. }
        | FieldType::StructRef(_)
        | FieldType::Computed { .. }
        | FieldType::EndiannessSwitch { .. } => None,
    }
}

fn decode<const N: usize, T>(
    raw: &[u8],
    endian: Endianness,
    little: fn([u8; N]) -> T,
    big: fn([u8; N]) -> T,
) -> Option<T> {
    let bytes: [u8; N] = raw.get(..N)?.try_into().ok()?;
    Some(match endian {
        Endianness::Little => little(bytes),
        Endianness::Big => big(bytes),
    })
}

fn format_scalar_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> Option<String> {
    Some(match ft {
        FieldType::UInt8 => {
            let v = *raw.first()?;
            format!("{v} (0x{v:02X})")
        }
        FieldType::Int8 => {
            let byte = *raw.first()?;
            let signed = i8::from_ne_bytes([byte]);
            format!("{signed} (0x{byte:02X})")
        }
        FieldType::Bool => {
            let text = if *raw.first()? == 0 { "false" } else { "true" };
            text.to_string()
        }
        FieldType::Char => {
            let ch = *raw.first()?;
            if ch.is_ascii_graphic() || ch == b' ' {
                format!("'{}' (0x{ch:02X})", ch as char)
            } else {
                format!("0x{ch:02X}")
            }
        }
        FieldType::UInt16 => {
            let v = decode(raw, endian, u16::from_le_bytes, u16::from_be_bytes)?;
            format!("{v} (0x{v:04X})")
        }
        FieldType::Int16 => {
            let v = decode(raw, endian, i16::from_le_bytes, i16::from_be_bytes)?;
            let u = u16::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:04X})")
        }
        FieldType::UInt32 => {
            let v = decode(raw, endian, u32::from_le_bytes, u32::from_be_bytes)?;
            format!("{v} (0x{v:08X})")
        }
        FieldType::Int32 => {
            let v = decode(raw, endian, i32::from_le_bytes, i32::from_be_bytes)?;
            let u = u32::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:08X})")
        }
        FieldType::UInt64 => {
            let v = decode(raw, endian, u64::from_le_bytes, u64::from_be_bytes)?;
            format!("{v} (0x{v:016X})")
        }
        FieldType::Int64 => {
            let v = decode(raw, endian, i64::from_le_bytes, i64::from_be_bytes)?;
            let u = u64::from_ne_bytes(v.to_ne_bytes());
            format!("{v} (0x{u:016X})")
        }
        FieldType::Float32 => {
            let v = decode(raw, endian, f32::from_le_bytes, f32::from_be_bytes)?;
            format!("{v}")
        }
        FieldType::Float64 => {
            let v = decode(raw, endian, f64::from_le_bytes, f64::from_be_bytes)?;
            format!("{v}")
        }
        _ => String::new(),
    })
}

fn format_composite_value(ft: &FieldType, raw: &[u8]) -> Option<String> {
    Some(match ft {
        FieldType::Bytes(n) => {
            let hex: Vec<String> = raw.get(..*n)?.iter().map(|b| format!("{b:02X}")).collect();
            hex.join(" ")
        }
        FieldType::FixedString(n) => {
            let s: String = raw
                .get(..*n)?
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
    })
}

/// The value of a field's `raw` bytes as its type displays it, or a note of how
/// many bytes were present when `raw` is shorter than the type needs.
#[must_use]
pub fn format_field_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> String {
    let formatted = match ft {
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
        | FieldType::Float64 => format_scalar_value(ft, raw, endian),
        _ => format_composite_value(ft, raw),
    };
    formatted.unwrap_or_else(|| {
        let needed = field_size(ft).unwrap_or(0);
        format!("<truncated: {} of {needed} bytes>", raw.len())
    })
}

/// The short lowercase name of a field type, such as `uint32` or
/// `dynamic_array`.
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

/// Narrows an IEEE-754 double to `i64`, truncating toward zero and saturating
/// at the integer bounds.
///
/// Every scalar field is reported to callers as an `i64`, so a float field has
/// to be narrowed somewhere. This walks the sign, exponent and mantissa apart
/// rather than leaning on a lossy primitive cast, which gives the edges of the
/// range answers that are part of the contract instead of incidental: `NaN`
/// reads as `0`, and a magnitude beyond the integer range clamps to `i64::MIN`
/// or `i64::MAX` rather than wrapping.
#[must_use]
fn float_to_i64_saturating(value: f64) -> i64 {
    const MANTISSA_BITS: u64 = 52;
    const EXPONENT_BIAS: u64 = 1023;
    const EXPONENT_MASK: u64 = 0x7ff;
    const MANTISSA_MASK: u64 = (1u64 << MANTISSA_BITS) - 1;
    const SIGN_SHIFT: u64 = 63;
    const MAGNITUDE_BITS: u64 = 63;

    let bits = value.to_bits();
    let negative = (bits >> SIGN_SHIFT) != 0;
    let biased = (bits >> MANTISSA_BITS) & EXPONENT_MASK;
    let mantissa = bits & MANTISSA_MASK;

    if biased == EXPONENT_MASK {
        if mantissa != 0 {
            return 0;
        }
        return if negative { i64::MIN } else { i64::MAX };
    }

    if biased < EXPONENT_BIAS {
        return 0;
    }
    let exponent = biased - EXPONENT_BIAS;

    if exponent >= MAGNITUDE_BITS {
        if negative && exponent == MAGNITUDE_BITS && mantissa == 0 {
            return i64::MIN;
        }
        return if negative { i64::MIN } else { i64::MAX };
    }

    let significand = (1u64 << MANTISSA_BITS) | mantissa;
    let magnitude = if exponent >= MANTISSA_BITS {
        significand << (exponent - MANTISSA_BITS)
    } else {
        significand >> (MANTISSA_BITS - exponent)
    };

    let magnitude = i64::try_from(magnitude).unwrap_or(i64::MAX);
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ScalarValue {
    Integer(i128),
    Float(f64),
}

impl ScalarValue {
    #[must_use]
    fn to_integer(self) -> i128 {
        match self {
            Self::Integer(v) => v,
            Self::Float(f) => i128::from(float_to_i64_saturating(f)),
        }
    }
}

#[must_use]
fn read_scalar_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> ScalarValue {
    let integer = ScalarValue::Integer;
    match ft {
        FieldType::UInt8 | FieldType::Char => integer(raw.first().copied().map_or(0, i128::from)),
        FieldType::Bool => integer(i128::from(raw.first().is_some_and(|b| *b != 0))),
        FieldType::Int8 => integer(
            raw.first()
                .map_or(0, |b| i128::from(i8::from_ne_bytes([*b]))),
        ),
        FieldType::UInt16 => integer(
            decode(raw, endian, u16::from_le_bytes, u16::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::Int16 => integer(
            decode(raw, endian, i16::from_le_bytes, i16::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::UInt32 => integer(
            decode(raw, endian, u32::from_le_bytes, u32::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::Int32 => integer(
            decode(raw, endian, i32::from_le_bytes, i32::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::UInt64 => integer(
            decode(raw, endian, u64::from_le_bytes, u64::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::Int64 => integer(
            decode(raw, endian, i64::from_le_bytes, i64::from_be_bytes).map_or(0, i128::from),
        ),
        FieldType::Float32 => decode(raw, endian, f32::from_le_bytes, f32::from_be_bytes)
            .map_or(ScalarValue::Integer(0), |v| {
                ScalarValue::Float(f64::from(v))
            }),
        FieldType::Float64 => decode(raw, endian, f64::from_le_bytes, f64::from_be_bytes)
            .map_or(ScalarValue::Integer(0), ScalarValue::Float),
        FieldType::Bitfield { backing_type, .. } | FieldType::Enum { backing_type, .. } => {
            read_scalar_value(backing_type, raw, endian)
        }
        FieldType::Pointer { pointer_type, .. } => read_scalar_value(pointer_type, raw, endian),
        // Bytes/FixedString/Array/Padding carry no single scalar value; 0 is
        // the only sensible placeholder for a field with no numeric meaning.
        _ => integer(0),
    }
}

/// The integer value of a field's `raw` bytes: integers, and the integers
/// behind bitfields, enums and pointers, exactly; floats truncated toward zero
/// and saturated; and 0 for a type with no single numeric value or for too few
/// bytes.
#[must_use]
pub fn read_numeric_value(ft: &FieldType, raw: &[u8], endian: Endianness) -> i128 {
    read_scalar_value(ft, raw, endian).to_integer()
}

#[must_use]
fn low_64_bits(value: i128) -> i64 {
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = value.to_le_bytes();
    i64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
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
        assert_ne!(list.len(), 0);
        assert!(list.iter().any(|(name, _)| name == "IMAGE_DOS_HEADER"));
    }

    #[test]
    fn test_apply_nonexistent() {
        let reg = TemplateRegistry::new();
        let result = reg.apply("NONEXISTENT", &[0u8; 100], 0);
        assert!(matches!(result, Err(TemplateError::NotFound(n)) if n == "NONEXISTENT"));
    }

    /// Every built-in that declares a magic declares the genuine format
    /// signature at offset 0, and these are exactly the built-ins that do:
    /// MZ, `\x7FELF`, the five Mach-O and fat magics, and the ZIP `PK` records.
    #[test]
    fn test_builtin_magic_bytes_are_the_genuine_signatures() {
        let expected: [(&str, &[u8]); 15] = [
            ("Elf32_Ehdr", &[0x7F, 0x45, 0x4C, 0x46]),
            ("Elf64_Ehdr", &[0x7F, 0x45, 0x4C, 0x46]),
            ("FAT_HEADER", &[0xCA, 0xFE, 0xBA, 0xBE]),
            ("IMAGE_DOS_HEADER", &[0x4D, 0x5A]),
            ("MACH_HEADER", &[0xCE, 0xFA, 0xED, 0xFE]),
            ("MACH_HEADER_64", &[0xCF, 0xFA, 0xED, 0xFE]),
            ("MACH_HEADER_64_BE", &[0xFE, 0xED, 0xFA, 0xCF]),
            ("MACH_HEADER_BE", &[0xFE, 0xED, 0xFA, 0xCE]),
            ("ZIP64_DATA_DESCRIPTOR", &[0x50, 0x4B, 0x07, 0x08]),
            ("ZIP64_EOCD_LOCATOR", &[0x50, 0x4B, 0x06, 0x07]),
            ("ZIP64_EOCD_RECORD", &[0x50, 0x4B, 0x06, 0x06]),
            ("ZIP_CENTRAL_DIRECTORY", &[0x50, 0x4B, 0x01, 0x02]),
            ("ZIP_DATA_DESCRIPTOR", &[0x50, 0x4B, 0x07, 0x08]),
            ("ZIP_END_OF_CENTRAL_DIRECTORY", &[0x50, 0x4B, 0x05, 0x06]),
            ("ZIP_LOCAL_FILE_HEADER", &[0x50, 0x4B, 0x03, 0x04]),
        ];
        let reg = TemplateRegistry::new();
        let mut declared: Vec<(String, usize, Vec<u8>)> = reg
            .templates
            .values()
            .filter_map(|t| {
                t.magic_detection
                    .as_ref()
                    .map(|m| (t.name.clone(), m.offset, m.bytes.clone()))
            })
            .collect();
        declared.sort();
        let expected: Vec<(String, usize, Vec<u8>)> = expected
            .iter()
            .map(|(name, bytes)| ((*name).to_string(), 0, bytes.to_vec()))
            .collect();
        assert_eq!(declared, expected);
        assert_eq!(reg.magic_extent(), 4);
    }

    /// `detect` names every template whose magic the data starts with, in
    /// name order, and nothing when the data is shorter than the magic.
    #[test]
    fn test_detect_names_the_templates_a_header_matches() {
        let reg = TemplateRegistry::new();
        let mut elf = vec![0x7F, b'E', b'L', b'F', 2, 1, 1];
        elf.resize(64, 0);
        assert_eq!(reg.detect(b"MZ\x90\x00\x03\x00"), vec!["IMAGE_DOS_HEADER"]);
        assert_eq!(reg.detect(&elf), vec!["Elf32_Ehdr", "Elf64_Ehdr"]);
        assert_eq!(
            reg.detect(b"PK\x07\x08\x00\x00"),
            vec!["ZIP64_DATA_DESCRIPTOR", "ZIP_DATA_DESCRIPTOR"]
        );
        assert_eq!(
            reg.detect(&[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1]),
            vec!["MACH_HEADER_64"]
        );
        assert_eq!(reg.detect(b"M"), Vec::<String>::new());
        assert_eq!(reg.detect(b"PK\x07"), Vec::<String>::new());
        assert_eq!(reg.detect(b"\x00\x00\x00\x00"), Vec::<String>::new());
    }

    /// A genuine linker-built DLL's first bytes are recognized as a DOS
    /// header and as nothing else.
    #[cfg(windows)]
    #[test]
    fn test_detect_recognizes_a_genuine_system_dll() {
        let dll = std::fs::read(r"C:\Windows\System32\kernel32.dll").unwrap();
        assert_eq!(
            TemplateRegistry::new().detect(&dll[..64]),
            vec!["IMAGE_DOS_HEADER"]
        );
    }

    #[test]
    fn test_apply_dos_header() {
        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;

        let reg = TemplateRegistry::new();
        let fields = reg.apply("IMAGE_DOS_HEADER", &data, 0).unwrap();
        assert_ne!(fields.len(), 0);
        assert_eq!(fields[0].name, "e_magic");
        assert_eq!(fields[0].display_value, "23117 (0x5A4D)");
    }

    #[test]
    fn test_insufficient_data() {
        let reg = TemplateRegistry::new();
        let result = reg.apply("IMAGE_DOS_HEADER", &[0u8; 10], 0);
        assert!(matches!(
            result,
            Err(TemplateError::InsufficientData { .. })
        ));
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
                    at: None,
                    name: "magic".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: "Magic number".to_string(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    at: None,
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
        assert_ne!(detailed.len(), 0);
        let dos = detailed
            .iter()
            .find(|(name, _, _, _)| name == "IMAGE_DOS_HEADER")
            .expect("IMAGE_DOS_HEADER must appear in list_detailed");
        assert_eq!(
            dos.3, 19,
            "IMAGE_DOS_HEADER must expose exactly 19 fields in list_detailed"
        );
    }

    #[test]
    fn test_format_field_value_integers_little_endian() {
        assert_eq!(
            format_field_value(&FieldType::UInt8, &[0x2A], Endianness::Little),
            "42 (0x2A)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int8, &[0xFF], Endianness::Little),
            "-1 (0xFF)"
        );
        assert_eq!(
            format_field_value(&FieldType::Bool, &[0x01], Endianness::Little),
            "true"
        );
        assert_eq!(
            format_field_value(&FieldType::Bool, &[0x00], Endianness::Little),
            "false"
        );
        assert_eq!(
            format_field_value(&FieldType::Char, &[0x41], Endianness::Little),
            "'A' (0x41)"
        );
        assert_eq!(
            format_field_value(&FieldType::Char, &[0x01], Endianness::Little),
            "0x01"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt16, &[0x34, 0x12], Endianness::Little),
            "4660 (0x1234)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Little),
            "-1 (0xFFFF)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::UInt32,
                &[0x78, 0x56, 0x34, 0x12],
                Endianness::Little
            ),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Int32,
                &[0xFF, 0xFF, 0xFF, 0xFF],
                Endianness::Little
            ),
            "-1 (0xFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::UInt64,
                &[1, 0, 0, 0, 0, 0, 0, 0],
                Endianness::Little
            ),
            "1 (0x0000000000000001)"
        );
        assert_eq!(
            format_field_value(&FieldType::Int64, &[0xFF; 8], Endianness::Little),
            "-1 (0xFFFFFFFFFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Float32,
                &1.5f32.to_le_bytes(),
                Endianness::Little
            ),
            "1.5"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Float64,
                &2.5f64.to_le_bytes(),
                Endianness::Little
            ),
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
            format_field_value(
                &FieldType::UInt32,
                &[0x12, 0x34, 0x56, 0x78],
                Endianness::Big
            ),
            "305419896 (0x12345678)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Int32,
                &[0xFF, 0xFF, 0xFF, 0xFF],
                Endianness::Big
            ),
            "-1 (0xFFFFFFFF)"
        );
        assert_eq!(
            format_field_value(
                &FieldType::UInt64,
                &[0, 0, 0, 0, 0, 0, 0, 1],
                Endianness::Big
            ),
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
            format_field_value(
                &FieldType::Bytes(3),
                &[0xAA, 0xBB, 0xCC],
                Endianness::Little
            ),
            "AA BB CC"
        );
        // Null-truncation + non-graphic byte -> '.'.
        assert_eq!(
            format_field_value(
                &FieldType::FixedString(4),
                &[0x41, 0x01, 0x42, 0x00],
                Endianness::Little
            ),
            "\"A.B\""
        );
        assert_eq!(
            format_field_value(
                &FieldType::Array {
                    element_type: Box::new(FieldType::UInt8),
                    count: 4
                },
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
                &FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "count".to_string()
                },
                &[],
                Endianness::Little
            ),
            "[dyn count x uint8]"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Bitfield {
                    bit_width: 3,
                    backing_type: Box::new(FieldType::UInt8),
                    flags: None
                },
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
                            at: None,
                            name: "a".to_string(),
                            field_type: FieldType::UInt8,
                            endianness: None,
                            description: String::new(),
                            color: None,
                            validation: None,
                        },
                        FieldDefinition {
                            at: None,
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
                &FieldType::Enum {
                    backing_type: Box::new(FieldType::UInt16),
                    values: vec![]
                },
                &[],
                Endianness::Little
            ),
            "enum<uint16>"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Pointer {
                    pointer_type: Box::new(FieldType::UInt32),
                    target_template: "FOO".to_string()
                },
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
            format_field_value(
                &FieldType::StructRef("BAR".to_string()),
                &[],
                Endianness::Little
            ),
            "struct BAR"
        );
        assert_eq!(
            format_field_value(
                &FieldType::Computed {
                    expression: "a+b".to_string(),
                    display_type: Box::new(FieldType::UInt32)
                },
                &[],
                Endianness::Little
            ),
            "= a+b"
        );
        assert_eq!(
            format_field_value(
                &FieldType::EndiannessSwitch {
                    peek_offset: 4,
                    big_value: 0xAB
                },
                &[],
                Endianness::Little
            ),
            "endianness_switch(peek+4==0xAB)"
        );
    }

    #[test]
    fn test_read_numeric_value_all_types_both_endian() {
        assert_eq!(
            read_numeric_value(&FieldType::UInt8, &[0x2A], Endianness::Little),
            42
        );
        assert_eq!(
            read_numeric_value(&FieldType::Bool, &[0x01], Endianness::Little),
            1
        );
        assert_eq!(
            read_numeric_value(&FieldType::Char, &[0x41], Endianness::Little),
            65
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int8, &[0xFF], Endianness::Little),
            -1
        );
        assert_eq!(
            read_numeric_value(&FieldType::UInt16, &[0x34, 0x12], Endianness::Little),
            4660
        );
        assert_eq!(
            read_numeric_value(&FieldType::UInt16, &[0x12, 0x34], Endianness::Big),
            4660
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Little),
            -1
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int16, &[0xFF, 0xFF], Endianness::Big),
            -1
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::UInt32,
                &[0x78, 0x56, 0x34, 0x12],
                Endianness::Little
            ),
            0x1234_5678
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::UInt32,
                &[0x12, 0x34, 0x56, 0x78],
                Endianness::Big
            ),
            0x1234_5678
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::Int32,
                &[0xFF, 0xFF, 0xFF, 0xFF],
                Endianness::Little
            ),
            -1
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::Int32,
                &[0xFF, 0xFF, 0xFF, 0xFF],
                Endianness::Big
            ),
            -1
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::UInt64,
                &[1, 0, 0, 0, 0, 0, 0, 0],
                Endianness::Little
            ),
            1
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::UInt64,
                &[0, 0, 0, 0, 0, 0, 0, 1],
                Endianness::Big
            ),
            1
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int64, &[0xFF; 8], Endianness::Little),
            -1
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int64, &[0xFF; 8], Endianness::Big),
            -1
        );
        // Zero-valued Float32 truncates to 0 (coincidental with the fallback
        // used by non-numeric composite types below).
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &[0; 4], Endianness::Little),
            0
        );
        // Non-numeric composite types (no single scalar value) fall through to 0.
        assert_eq!(
            read_numeric_value(&FieldType::Bytes(2), &[0; 2], Endianness::Little),
            0
        );
    }

    #[test]
    fn test_read_numeric_value_float_truncates_to_real_value() {
        assert_eq!(
            read_numeric_value(
                &FieldType::Float32,
                &7.9f32.to_le_bytes(),
                Endianness::Little
            ),
            7
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::Float64,
                &(-3.9f64).to_le_bytes(),
                Endianness::Little
            ),
            -3
        );
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &7.9f32.to_be_bytes(), Endianness::Big),
            7
        );
    }

    #[test]
    fn test_field_size_option_semantics() {
        assert_eq!(field_size(&FieldType::UInt32), Some(4));
        assert_eq!(field_size(&FieldType::Padding(0)), Some(0));
        assert_eq!(field_size(&FieldType::StructRef("X".to_string())), None);
        assert_eq!(
            field_size(&FieldType::Computed {
                expression: "1".to_string(),
                display_type: Box::new(FieldType::UInt8),
            }),
            None
        );

        // Array of a statically sized element resolves normally.
        assert_eq!(
            field_size(&FieldType::Array {
                element_type: Box::new(FieldType::UInt32),
                count: 5,
            }),
            Some(20)
        );

        assert_eq!(
            field_size(&FieldType::Array {
                element_type: Box::new(FieldType::StructRef("Elem".to_string())),
                count: 3,
            }),
            None
        );

        // Array size overflow (element_size * count > usize::MAX) is
        // reported as None rather than silently wrapping to a small value.
        assert_eq!(
            field_size(&FieldType::Array {
                element_type: Box::new(FieldType::UInt64),
                count: usize::MAX / 4,
            }),
            None
        );
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
        assert_eq!(
            field_type_name(&FieldType::Array {
                element_type: Box::new(FieldType::UInt8),
                count: 1
            }),
            "array"
        );
        assert_eq!(field_type_name(&FieldType::Bool), "bool");
        assert_eq!(field_type_name(&FieldType::Char), "char");
        assert_eq!(field_type_name(&FieldType::Padding(1)), "padding");
    }

    #[test]
    fn test_field_type_name_composite_variants() {
        assert_eq!(
            field_type_name(&FieldType::DynamicArray {
                element_type: Box::new(FieldType::UInt8),
                count_field: "c".to_string()
            }),
            "dynamic_array"
        );
        assert_eq!(
            field_type_name(&FieldType::Bitfield {
                bit_width: 1,
                backing_type: Box::new(FieldType::UInt8),
                flags: None
            }),
            "bitfield"
        );
        assert_eq!(
            field_type_name(&FieldType::Union { variants: vec![] }),
            "union"
        );
        assert_eq!(
            field_type_name(&FieldType::Enum {
                backing_type: Box::new(FieldType::UInt8),
                values: vec![]
            }),
            "enum"
        );
        assert_eq!(
            field_type_name(&FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt8),
                target_template: "t".to_string()
            }),
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
        assert_eq!(
            field_type_name(&FieldType::StructRef("s".to_string())),
            "struct_ref"
        );
        assert_eq!(
            field_type_name(&FieldType::Computed {
                expression: "e".to_string(),
                display_type: Box::new(FieldType::UInt8)
            }),
            "computed"
        );
        assert_eq!(
            field_type_name(&FieldType::EndiannessSwitch {
                peek_offset: 0,
                big_value: 0
            }),
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

    #[test]
    fn test_float_to_i64_truncates_toward_zero() {
        assert_eq!(float_to_i64_saturating(0.0), 0);
        assert_eq!(float_to_i64_saturating(-0.0), 0);
        assert_eq!(float_to_i64_saturating(0.5), 0);
        assert_eq!(float_to_i64_saturating(-0.5), 0);
        assert_eq!(float_to_i64_saturating(f64::from_bits(1)), 0);
        assert_eq!(float_to_i64_saturating(3.75), 3);
        assert_eq!(float_to_i64_saturating(-3.75), -3);
        assert_eq!(float_to_i64_saturating(1.0), 1);
        assert_eq!(float_to_i64_saturating(-1.0), -1);
        assert_eq!(float_to_i64_saturating(1.0e15), 1_000_000_000_000_000);
        assert_eq!(float_to_i64_saturating(-1.0e15), -1_000_000_000_000_000);
    }

    #[test]
    fn test_float_to_i64_saturates_at_bounds() {
        assert_eq!(float_to_i64_saturating(f64::NAN), 0);
        assert_eq!(float_to_i64_saturating(-f64::NAN), 0);
        assert_eq!(float_to_i64_saturating(f64::INFINITY), i64::MAX);
        assert_eq!(float_to_i64_saturating(f64::NEG_INFINITY), i64::MIN);
        assert_eq!(float_to_i64_saturating(f64::MAX), i64::MAX);
        assert_eq!(float_to_i64_saturating(f64::MIN), i64::MIN);

        assert_eq!(
            float_to_i64_saturating(4_611_686_018_427_387_904.0),
            4_611_686_018_427_387_904
        );
        assert_eq!(
            float_to_i64_saturating(9_223_372_036_854_774_784.0),
            9_223_372_036_854_774_784
        );
        assert_eq!(
            float_to_i64_saturating(-9_223_372_036_854_774_784.0),
            -9_223_372_036_854_774_784
        );

        assert_eq!(
            float_to_i64_saturating(9_223_372_036_854_775_808.0),
            i64::MAX
        );
        assert_eq!(
            float_to_i64_saturating(-9_223_372_036_854_775_808.0),
            i64::MIN
        );
    }

    #[test]
    fn test_read_numeric_value_floats() {
        let little_double = 3.75f64.to_le_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float64, &little_double, Endianness::Little),
            3
        );
        let big_double = (-3.75f64).to_be_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float64, &big_double, Endianness::Big),
            -3
        );
        let unbounded_double = f64::NEG_INFINITY.to_le_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float64, &unbounded_double, Endianness::Little),
            i128::from(i64::MIN)
        );

        let little_single = 1.0e9f32.to_le_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &little_single, Endianness::Little),
            1_000_000_000
        );
        let big_single = (-2.5f32).to_be_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &big_single, Endianness::Big),
            -2
        );
        let undefined_single = f32::NAN.to_le_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &undefined_single, Endianness::Little),
            0
        );
        let overlarge_single = 1.0e30f32.to_le_bytes();
        assert_eq!(
            read_numeric_value(&FieldType::Float32, &overlarge_single, Endianness::Little),
            i128::from(i64::MAX)
        );
    }

    #[test]
    fn test_u64_read_numeric_value_is_exact() {
        assert_eq!(
            read_numeric_value(&FieldType::UInt64, &[0xFF; 8], Endianness::Little),
            18_446_744_073_709_551_615
        );
        assert_eq!(
            read_numeric_value(
                &FieldType::UInt64,
                &0x8000_0000_0000_0000u64.to_be_bytes(),
                Endianness::Big
            ),
            9_223_372_036_854_775_808
        );
        assert_eq!(
            read_numeric_value(&FieldType::Int64, &[0xFF; 8], Endianness::Little),
            -1
        );
        assert_eq!(low_64_bits(18_446_744_073_709_551_615), -1);
        assert_eq!(low_64_bits(9_223_372_036_854_775_808), i64::MIN);
        assert_eq!(low_64_bits(i128::from(i64::MIN)), i64::MIN);
        assert_eq!(low_64_bits(7), 7);
    }

    #[test]
    fn test_bool_reads_as_zero_or_one() {
        let read = |ft: &FieldType, byte: u8| read_numeric_value(ft, &[byte], Endianness::Little);
        assert_eq!(read(&FieldType::Bool, 0x00), 0);
        assert_eq!(read(&FieldType::Bool, 0x01), 1);
        assert_eq!(read(&FieldType::Bool, 0x02), 1);
        assert_eq!(read(&FieldType::Bool, 0xFF), 1);
        assert_eq!(read(&FieldType::UInt8, 0x02), 2);
        assert_eq!(read(&FieldType::Char, 0x41), 65);
        assert_eq!(
            format_field_value(&FieldType::Bool, &[0x02], Endianness::Little),
            "true"
        );
    }

    #[test]
    fn test_read_numeric_value_sees_through_wrappers() {
        let enum_u16 = FieldType::Enum {
            backing_type: Box::new(FieldType::UInt16),
            values: Vec::new(),
        };
        let bitfield_u32 = FieldType::Bitfield {
            bit_width: 4,
            backing_type: Box::new(FieldType::UInt32),
            flags: None,
        };
        let pointer_to_enum = FieldType::Pointer {
            pointer_type: Box::new(enum_u16.clone()),
            target_template: "T".to_string(),
        };

        assert_eq!(
            read_numeric_value(&enum_u16, &[0x34, 0x12], Endianness::Little),
            0x1234
        );
        assert_eq!(
            read_numeric_value(&enum_u16, &[0x12, 0x34], Endianness::Big),
            0x1234
        );
        assert_eq!(
            read_numeric_value(&bitfield_u32, &[0x78, 0x56, 0x34, 0x12], Endianness::Little),
            0x1234_5678
        );
        assert_eq!(
            read_numeric_value(&pointer_to_enum, &[0x34, 0x12], Endianness::Little),
            0x1234
        );
        assert_eq!(
            read_scalar_value(
                &FieldType::Pointer {
                    pointer_type: Box::new(FieldType::Float32),
                    target_template: "T".to_string(),
                },
                &2.5f32.to_le_bytes(),
                Endianness::Little
            ),
            ScalarValue::Float(2.5)
        );
    }

    #[test]
    fn test_short_buffers_never_panic() {
        let little = Endianness::Little;
        assert_eq!(
            format_field_value(&FieldType::UInt8, &[], little),
            "<truncated: 0 of 1 bytes>"
        );
        assert_eq!(
            format_field_value(&FieldType::UInt32, &[1, 2], little),
            "<truncated: 2 of 4 bytes>"
        );
        assert_eq!(
            format_field_value(&FieldType::Int64, &[0xFF; 7], Endianness::Big),
            "<truncated: 7 of 8 bytes>"
        );
        assert_eq!(
            format_field_value(&FieldType::Float64, &[0; 3], little),
            "<truncated: 3 of 8 bytes>"
        );
        assert_eq!(
            format_field_value(&FieldType::Bytes(4), &[0xAA, 0xBB], little),
            "<truncated: 2 of 4 bytes>"
        );
        assert_eq!(
            format_field_value(&FieldType::FixedString(3), &[], little),
            "<truncated: 0 of 3 bytes>"
        );
        assert_eq!(format_field_value(&FieldType::Bytes(0), &[], little), "");
        assert_eq!(
            format_field_value(&FieldType::Padding(8), &[], little),
            "padding[8]"
        );

        for ft in [
            FieldType::UInt8,
            FieldType::Int16,
            FieldType::UInt32,
            FieldType::Int64,
            FieldType::UInt64,
            FieldType::Float32,
            FieldType::Float64,
            FieldType::Bool,
            FieldType::Char,
        ] {
            assert_eq!(read_numeric_value(&ft, &[], little), 0);
        }
        assert_eq!(
            read_numeric_value(&FieldType::UInt64, &[1, 2, 3], little),
            0
        );
        assert_eq!(
            read_scalar_value(&FieldType::Float64, &[1], little),
            ScalarValue::Integer(0)
        );
    }
}
