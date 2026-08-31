use super::{StructTemplate, TemplateError};

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
        validate_field_type(&field.field_type)?;
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

fn validate_field_type(ft: &super::FieldType) -> Result<(), TemplateError> {
    match ft {
        super::FieldType::DynamicArray {
            element_type,
            count_field,
        } => {
            if count_field.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "DynamicArray count_field cannot be empty".to_string(),
                ));
            }
            validate_field_type(element_type)?;
            if super::field_size(element_type).is_none() {
                return Err(TemplateError::InvalidFieldReference(
                    "DynamicArray element_type must have a statically known size".to_string(),
                ));
            }
        }
        super::FieldType::Conditional {
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
                validate_field_type(&f.field_type)?;
            }
        }
        super::FieldType::Pointer {
            pointer_type,
            target_template,
        } => {
            if target_template.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "Pointer target_template cannot be empty".to_string(),
                ));
            }
            validate_field_type(pointer_type)?;
        }
        super::FieldType::StructRef(name) if name.is_empty() => {
            return Err(TemplateError::InvalidFieldReference(
                "StructRef name cannot be empty".to_string(),
            ));
        }
        super::FieldType::Array {
            element_type,
            count,
        } => {
            validate_field_type(element_type)?;
            match super::field_size(element_type) {
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
        super::FieldType::Bitfield { backing_type, .. }
        | super::FieldType::Enum { backing_type, .. } => {
            validate_field_type(backing_type)?;
        }
        super::FieldType::Union { variants } => {
            for v in variants {
                validate_field_type(&v.field_type)?;
            }
        }
        super::FieldType::Computed { display_type, .. } => {
            validate_field_type(display_type)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::{ConditionOp, FieldDefinition, FieldType};

    fn bad_ptr() -> FieldType {
        // Pointer with an empty target_template is invalid.
        FieldType::Pointer {
            pointer_type: Box::new(FieldType::UInt32),
            target_template: String::new(),
        }
    }

    fn fdef(ft: FieldType) -> FieldDefinition {
        FieldDefinition {
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

    /// Audit F-0008 regression: an `Array` whose element type has no
    /// static size (composite/self-recursive) must be rejected at
    /// registration time rather than silently sizing to 0 and corrupting
    /// every later sibling field's offset at evaluation time.
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

    /// Audit F-0023 regression: a `DynamicArray` whose element type has no
    /// static size defeats the runtime `InsufficientData` guard (its size
    /// multiplies to 0 regardless of `count`); reject it up front.
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

    /// Audit F-0026 regression: an `Array` whose `element_size * count`
    /// would overflow `usize` must be rejected at registration time.
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

    /// Wave-5 gate: assert the exact error variant and message for empty template name.
    ///
    /// The weak gate above only asserts `is_err()`.  This test asserts the
    /// concrete `TemplateError::JsonParse` variant *and* that its message
    /// contains the documented string "template name cannot be empty".
    ///
    /// Mutation caught: replacing `TemplateError::JsonParse(...)` with any other
    /// variant (or changing the message text) fails the `matches!` predicate.
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

    /// Wave-5 gate: assert the exact error variant and message for an empty `DynamicArray`
    /// `count_field`.
    ///
    /// The weak gate above only asserts `is_err()`.  This test asserts the concrete
    /// `TemplateError::InvalidFieldReference` variant *and* that its message contains
    /// `count_field`.
    ///
    /// Mutation caught: returning `TemplateError::JsonParse` instead of
    /// `TemplateError::InvalidFieldReference`, or omitting `count_field` from
    /// the message, fails the `matches!` predicate.
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

    /// Wave-5 gate: assert `TemplateError::InvalidFieldReference` is returned for a
    /// Conditional field whose `condition_field` is an empty string.
    ///
    /// This is the only test for the guard at `json_schema.rs:53`.  No test existed
    /// before this wave.
    ///
    /// Oracle: the production source at line 53-56 returns
    ///   `TemplateError::InvalidFieldReference("Conditional condition_field cannot be empty")`
    /// when `condition_field.is_empty()`.  We assert exactly this variant and that
    /// the message contains `condition_field`.
    ///
    /// Mutation caught: removing or inverting the `is_empty()` guard would allow the
    /// call to proceed (returning `Ok`) instead of failing, causing `unwrap_err()` to
    /// panic.  Changing the error variant would cause the `matches!` predicate to fail.
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
}
