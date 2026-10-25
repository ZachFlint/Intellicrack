// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

use super::{eval, field_size, FieldDefinition, FieldType, StructTemplate, TemplateError};

/// Parse a JSON string into a `StructTemplate`.
///
/// # Errors
///
/// Returns `TemplateError::JsonParse` if the JSON is malformed or missing required fields,
/// or `TemplateError::InvalidFieldReference` if field type references are invalid.
pub fn parse_json_template(json_str: &str) -> Result<StructTemplate, TemplateError> {
    let template: StructTemplate =
        serde_json::from_str(json_str).map_err(|e| TemplateError::JsonParse(e.to_string()))?;

    if template.name.is_empty() {
        return Err(TemplateError::JsonParse(
            "template name cannot be empty".to_string(),
        ));
    }

    for field in &template.fields {
        validate_field(field)?;
    }

    Ok(template)
}

/// Serialize a `StructTemplate` to a pretty-printed JSON string.
///
/// # Errors
///
/// Returns `TemplateError::JsonParse` if serialization fails.
pub fn template_to_json(template: &StructTemplate) -> Result<String, TemplateError> {
    serde_json::to_string_pretty(template).map_err(|e| TemplateError::JsonParse(e.to_string()))
}

fn require_static_size(ft: &FieldType, what: &str) -> Result<(), TemplateError> {
    if field_size(ft).is_none() {
        return Err(TemplateError::InvalidFieldReference(format!(
            "{what} must have a statically known size"
        )));
    }
    Ok(())
}

fn validate_field(field: &FieldDefinition) -> Result<(), TemplateError> {
    if let Some(expression) = &field.at {
        eval::check_expression_syntax(expression).map_err(|e| {
            TemplateError::InvalidFieldReference(format!(
                "field '{}' has an invalid at expression: {e}",
                field.name
            ))
        })?;
    }
    validate_field_type(&field.field_type)
}

fn validate_bitfield(bit_width: u8, backing_type: &FieldType) -> Result<(), TemplateError> {
    validate_field_type(backing_type)?;
    require_static_size(backing_type, "Bitfield backing_type")?;
    if bit_width == 0 {
        return Err(TemplateError::InvalidFieldReference(
            "Bitfield bit_width must be at least 1".to_string(),
        ));
    }
    if let Some(size) = field_size(backing_type) {
        let capacity = size.saturating_mul(8);
        if usize::from(bit_width) > capacity {
            return Err(TemplateError::InvalidFieldReference(format!(
                "Bitfield bit_width {bit_width} exceeds the {capacity}-bit backing type"
            )));
        }
    }
    Ok(())
}

fn validate_field_type(ft: &FieldType) -> Result<(), TemplateError> {
    match ft {
        FieldType::DynamicArray {
            element_type,
            count_field,
        } => {
            if count_field.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "DynamicArray count_field cannot be empty".to_string(),
                ));
            }
            validate_field_type(element_type)?;
            if field_size(element_type).is_none() {
                return Err(TemplateError::InvalidFieldReference(
                    "DynamicArray element_type must have a statically known size".to_string(),
                ));
            }
        }
        FieldType::Conditional {
            condition_field,
            fields,
            ..
        } => {
            if condition_field.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "Conditional condition_field cannot be empty".to_string(),
                ));
            }
            for f in fields {
                validate_field(f)?;
            }
        }
        FieldType::Pointer {
            pointer_type,
            target_template,
        } => {
            if target_template.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "Pointer target_template cannot be empty".to_string(),
                ));
            }
            validate_field_type(pointer_type)?;
            require_static_size(pointer_type, "Pointer pointer_type")?;
        }
        FieldType::StructRef(name) if name.is_empty() => {
            return Err(TemplateError::InvalidFieldReference(
                "StructRef name cannot be empty".to_string(),
            ));
        }
        FieldType::Array {
            element_type,
            count,
        } => {
            validate_field_type(element_type)?;
            match field_size(element_type) {
                None => {
                    return Err(TemplateError::InvalidFieldReference(
                        "Array element_type must have a statically known size".to_string(),
                    ));
                }
                Some(elem_size) => {
                    if elem_size.checked_mul(*count).is_none() {
                        return Err(TemplateError::InvalidFieldReference(
                            "Array element_type size multiplied by count overflows".to_string(),
                        ));
                    }
                }
            }
        }
        FieldType::Bitfield {
            bit_width,
            backing_type,
            ..
        } => validate_bitfield(*bit_width, backing_type)?,
        FieldType::Enum { backing_type, .. } => {
            validate_field_type(backing_type)?;
            require_static_size(backing_type, "Enum backing_type")?;
        }
        FieldType::Union { variants } => {
            for v in variants {
                validate_field(v)?;
            }
        }
        FieldType::Computed {
            expression,
            display_type,
        } => {
            eval::check_expression_syntax(expression).map_err(|e| {
                TemplateError::InvalidFieldReference(format!(
                    "Computed field has an invalid expression: {e}"
                ))
            })?;
            validate_field_type(display_type)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::{ConditionOp, TemplateRegistry};

    fn bad_ptr() -> FieldType {
        // Pointer with an empty target_template is invalid.
        FieldType::Pointer {
            pointer_type: Box::new(FieldType::UInt32),
            target_template: String::new(),
        }
    }

    fn fdef(ft: FieldType) -> FieldDefinition {
        FieldDefinition {
            at: None,
            name: "inner".to_string(),
            field_type: ft,
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }
    }

    fn assert_bad_target(ft: &FieldType) {
        let err = validate_field_type(ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("target_template")),
            "expected nested target_template error, got {err:?}"
        );
    }

    /// A Computed field whose expression contains an invalid token must be
    /// rejected at validation time, the same way an `at` expression is, not
    /// accepted and then failed late at evaluation.
    #[test]
    fn test_validate_rejects_computed_with_bad_expression_syntax() {
        let ft = FieldType::Computed {
            expression: "1 @ 2".to_string(),
            display_type: Box::new(FieldType::UInt8),
        };
        let err = validate_field_type(&ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("expression")),
            "got {err:?}"
        );
        // A well-formed expression still validates.
        let ok = FieldType::Computed {
            expression: "1 + 2".to_string(),
            display_type: Box::new(FieldType::UInt8),
        };
        assert!(validate_field_type(&ok).is_ok());
    }

    /// A Bitfield whose `bit_width` is zero or exceeds its backing type must be
    /// rejected at validation time; a zero width would mask every value to 0.
    #[test]
    fn test_validate_rejects_zero_and_oversized_bitfield_width() {
        let zero = FieldType::Bitfield {
            bit_width: 0,
            backing_type: Box::new(FieldType::UInt8),
            flags: None,
        };
        assert!(
            matches!(validate_field_type(&zero).unwrap_err(),
                TemplateError::InvalidFieldReference(ref m) if m.contains("at least 1")),
            "zero width must be rejected"
        );
        let oversized = FieldType::Bitfield {
            bit_width: 9,
            backing_type: Box::new(FieldType::UInt8),
            flags: None,
        };
        assert!(
            matches!(validate_field_type(&oversized).unwrap_err(),
                TemplateError::InvalidFieldReference(ref m) if m.contains("exceeds")),
            "width past the backing type must be rejected"
        );
        let valid = FieldType::Bitfield {
            bit_width: 8,
            backing_type: Box::new(FieldType::UInt8),
            flags: None,
        };
        assert!(validate_field_type(&valid).is_ok());
    }

    #[test]
    fn test_validate_pointer_empty_target() {
        let err = validate_field_type(&bad_ptr()).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("target_template")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_struct_ref_empty_name() {
        let err = validate_field_type(&FieldType::StructRef(String::new())).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("StructRef name")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_nested_invalid_propagates_through_wrappers() {
        // Array
        assert_bad_target(&FieldType::Array {
            element_type: Box::new(bad_ptr()),
            count: 2,
        });
        // Bitfield backing type
        assert_bad_target(&FieldType::Bitfield {
            bit_width: 4,
            backing_type: Box::new(bad_ptr()),
            flags: None,
        });
        // Enum backing type
        assert_bad_target(&FieldType::Enum {
            backing_type: Box::new(bad_ptr()),
            values: vec![],
        });
        // Union variant
        assert_bad_target(&FieldType::Union {
            variants: vec![fdef(bad_ptr())],
        });
        // Computed display type
        assert_bad_target(&FieldType::Computed {
            expression: "x".to_string(),
            display_type: Box::new(bad_ptr()),
        });
        // DynamicArray element type (count_field non-empty so recursion is reached)
        assert_bad_target(&FieldType::DynamicArray {
            element_type: Box::new(bad_ptr()),
            count_field: "n".to_string(),
        });
        // Conditional inner field
        assert_bad_target(&FieldType::Conditional {
            condition_field: "f".to_string(),
            condition_value: 0,
            condition_op: ConditionOp::Eq,
            fields: vec![fdef(bad_ptr())],
        });
    }

    #[test]
    fn test_validate_array_element_type_must_be_sized() {
        let ft = FieldType::Array {
            element_type: Box::new(FieldType::StructRef("Foo".to_string())),
            count: 3,
        };
        let err = validate_field_type(&ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("statically known size")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_dynamic_array_element_type_must_be_sized() {
        let ft = FieldType::DynamicArray {
            element_type: Box::new(FieldType::Union { variants: vec![] }),
            count_field: "n".to_string(),
        };
        let err = validate_field_type(&ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("statically known size")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_array_count_overflow_rejected() {
        let ft = FieldType::Array {
            element_type: Box::new(FieldType::UInt64),
            count: usize::MAX / 4,
        };
        let err = validate_field_type(&ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("overflows")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_valid_wrappers_ok() {
        assert!(validate_field_type(&FieldType::UInt8).is_ok());
        assert!(validate_field_type(&FieldType::Array {
            element_type: Box::new(FieldType::UInt8),
            count: 4,
        })
        .is_ok());
        assert!(validate_field_type(&FieldType::Pointer {
            pointer_type: Box::new(FieldType::UInt32),
            target_template: "Valid".to_string(),
        })
        .is_ok());
    }

    #[test]
    fn test_parse_simple_template() {
        let json = r#"{
            "name": "SIMPLE",
            "description": "Simple test",
            "default_endianness": "little",
            "fields": [
                {"name": "a", "field_type": {"type": "UInt8"}, "description": ""},
                {"name": "b", "field_type": {"type": "UInt32"}, "description": ""}
            ]
        }"#;
        let tmpl = parse_json_template(json).unwrap();
        assert_eq!(tmpl.name, "SIMPLE");
        assert_eq!(tmpl.fields.len(), 2);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_json_template("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_name() {
        let json =
            r#"{"name": "", "description": "", "default_endianness": "little", "fields": []}"#;
        let result = parse_json_template(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_name_exact_error_variant_and_message() {
        let json =
            r#"{"name": "", "description": "", "default_endianness": "little", "fields": []}"#;
        let result = parse_json_template(json);
        let err = result.unwrap_err();
        assert!(
            matches!(err, TemplateError::JsonParse(ref msg) if msg.contains("template name cannot be empty")),
            "expected TemplateError::JsonParse(msg) containing 'template name cannot be empty', got: {err:?}"
        );
    }

    #[test]
    fn test_roundtrip() {
        let json = r#"{
            "name": "RT_TEST",
            "description": "Roundtrip",
            "default_endianness": "big",
            "fields": [
                {"name": "magic", "field_type": {"type": "UInt16"}, "description": "Magic"},
                {"name": "data", "field_type": {"type": "Bytes", "params": 4}, "description": "Data"}
            ]
        }"#;
        let tmpl = parse_json_template(json).unwrap();
        let exported = template_to_json(&tmpl).unwrap();
        let tmpl2 = parse_json_template(&exported).unwrap();
        assert_eq!(tmpl.name, tmpl2.name);
        assert_eq!(tmpl.fields.len(), tmpl2.fields.len());
    }

    #[test]
    fn test_parse_with_new_types() {
        let json = r#"{
            "name": "ADVANCED",
            "description": "Advanced types",
            "default_endianness": "little",
            "fields": [
                {"name": "flag", "field_type": {"type": "Bool"}, "description": ""},
                {"name": "pad", "field_type": {"type": "Padding", "params": 3}, "description": ""},
                {"name": "ch", "field_type": {"type": "Char"}, "description": ""},
                {
                    "name": "items",
                    "field_type": {
                        "type": "DynamicArray",
                        "params": {"element_type": {"type": "UInt8"}, "count_field": "flag"}
                    },
                    "description": ""
                }
            ]
        }"#;
        let tmpl = parse_json_template(json).unwrap();
        assert_eq!(tmpl.fields.len(), 4);
    }

    #[test]
    fn test_invalid_dynamic_array_ref() {
        let json = r#"{
            "name": "BAD",
            "description": "",
            "default_endianness": "little",
            "fields": [{
                "name": "x",
                "field_type": {
                    "type": "DynamicArray",
                    "params": {"element_type": {"type": "UInt8"}, "count_field": ""}
                },
                "description": ""
            }]
        }"#;
        let result = parse_json_template(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_dynamic_array_ref_exact_error_variant_and_message() {
        let json = r#"{
            "name": "BAD_DA",
            "description": "",
            "default_endianness": "little",
            "fields": [{
                "name": "x",
                "field_type": {
                    "type": "DynamicArray",
                    "params": {"element_type": {"type": "UInt8"}, "count_field": ""}
                },
                "description": ""
            }]
        }"#;
        let result = parse_json_template(json);
        let err = result.unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidFieldReference(ref msg) if msg.contains("count_field")),
            "expected TemplateError::InvalidFieldReference(msg) containing 'count_field', got: {err:?}"
        );
    }

    #[test]
    fn test_invalid_conditional_empty_condition_field_exact_error_variant() {
        let json = r#"{
            "name": "BAD_COND",
            "description": "",
            "default_endianness": "little",
            "fields": [{
                "name": "maybe_field",
                "field_type": {
                    "type": "Conditional",
                    "params": {
                        "condition_field": "",
                        "condition_value": 0,
                        "condition_op": "Eq",
                        "fields": []
                    }
                },
                "description": ""
            }]
        }"#;
        let result = parse_json_template(json);
        let err = result.unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidFieldReference(ref msg) if msg.contains("condition_field")),
            "expected TemplateError::InvalidFieldReference(msg) containing 'condition_field', got: {err:?}"
        );
    }

    fn assert_unsized(ft: &FieldType, expected: &str) {
        let err = validate_field_type(ft).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m)
                if m == &format!("{expected} must have a statically known size")),
            "expected '{expected} must have a statically known size', got {err:?}"
        );
    }

    #[test]
    fn test_unsized_pointer_type_rejected_at_registration() {
        assert_unsized(
            &FieldType::Pointer {
                pointer_type: Box::new(FieldType::StructRef("Foo".to_string())),
                target_template: "T".to_string(),
            },
            "Pointer pointer_type",
        );
        assert_unsized(
            &FieldType::Pointer {
                pointer_type: Box::new(FieldType::Union { variants: vec![] }),
                target_template: "T".to_string(),
            },
            "Pointer pointer_type",
        );

        let json = r#"{
            "name": "BAD_PTR",
            "description": "",
            "default_endianness": "little",
            "fields": [{
                "name": "p",
                "field_type": {
                    "type": "Pointer",
                    "params": {
                        "pointer_type": {"type": "StructRef", "params": "Foo"},
                        "target_template": "T"
                    }
                },
                "description": ""
            }]
        }"#;
        let err = parse_json_template(json).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m)
                if m.contains("Pointer pointer_type must have a statically known size")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_unsized_enum_and_bitfield_backing_rejected() {
        let unsized_type = || Box::new(FieldType::StructRef("Foo".to_string()));
        let bad_enum = FieldType::Enum {
            backing_type: unsized_type(),
            values: vec![],
        };
        let bad_bitfield = FieldType::Bitfield {
            bit_width: 3,
            backing_type: unsized_type(),
            flags: None,
        };
        assert_unsized(&bad_enum, "Enum backing_type");
        assert_unsized(&bad_bitfield, "Bitfield backing_type");

        assert_unsized(
            &FieldType::Conditional {
                condition_field: "f".to_string(),
                condition_value: 0,
                condition_op: ConditionOp::Eq,
                fields: vec![fdef(bad_enum)],
            },
            "Enum backing_type",
        );
        assert_unsized(
            &FieldType::Union {
                variants: vec![fdef(bad_bitfield)],
            },
            "Bitfield backing_type",
        );

        assert!(validate_field_type(&FieldType::Enum {
            backing_type: Box::new(FieldType::UInt16),
            values: vec![],
        })
        .is_ok());
        assert!(validate_field_type(&FieldType::Bitfield {
            bit_width: 3,
            backing_type: Box::new(FieldType::Enum {
                backing_type: Box::new(FieldType::UInt8),
                values: vec![],
            }),
            flags: None,
        })
        .is_ok());
    }

    #[test]
    fn test_at_expression_round_trips_and_is_validated() {
        let json = r#"{
            "name": "AT_TEST",
            "description": "",
            "default_endianness": "little",
            "fields": [
                {"name": "n", "field_type": {"type": "UInt8"}, "description": ""},
                {"name": "late", "field_type": {"type": "UInt8"}, "description": "", "at": "n + 1"}
            ]
        }"#;
        let template = parse_json_template(json).unwrap();
        assert_eq!(template.fields[0].at, None);
        assert_eq!(template.fields[1].at.as_deref(), Some("n + 1"));

        let exported = template_to_json(&template).unwrap();
        let value: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(value["fields"][1]["at"].as_str(), Some("n + 1"));
        assert!(value["fields"][0].get("at").is_none());
        let again = parse_json_template(&exported).unwrap();
        assert_eq!(again.fields[1].at.as_deref(), Some("n + 1"));

        let with_at = |at: &str, nested: bool| {
            let field = FieldDefinition {
                at: Some(at.to_string()),
                ..fdef(FieldType::UInt8)
            };
            let field = if nested {
                fdef(FieldType::Conditional {
                    condition_field: "n".to_string(),
                    condition_value: 0,
                    condition_op: ConditionOp::Eq,
                    fields: vec![field],
                })
            } else {
                field
            };
            validate_field(&field)
        };
        for nested in [false, true] {
            assert!(with_at("n + 1", nested).is_ok());
            for bad in ["", "   ", "1 @ 2", "0x"] {
                let err = with_at(bad, nested).unwrap_err();
                assert!(
                    matches!(&err, TemplateError::InvalidFieldReference(m)
                        if m.contains("field 'inner' has an invalid at expression")),
                    "at {bad:?} nested={nested}: got {err:?}"
                );
            }
        }
    }

    #[test]
    fn test_builtin_templates_survive_json_round_trip() {
        let reg = TemplateRegistry::new();
        for (name, _) in reg.list() {
            let json = reg.export_json(&name).unwrap();
            let parsed = parse_json_template(&json)
                .unwrap_or_else(|e| panic!("built-in {name} failed to re-register: {e}"));
            assert_eq!(template_to_json(&parsed).unwrap(), json, "{name}");
        }

        let exported = reg.export_json("DYLIB_COMMAND_BE").unwrap();
        let dylib = parse_json_template(&exported).unwrap();
        let name_field = dylib.fields.iter().find(|f| f.name == "name").unwrap();
        assert_eq!(name_field.at.as_deref(), Some("name_offset"));
    }
}
