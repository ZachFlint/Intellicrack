use super::{StructTemplate, TemplateError};

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
        super::FieldType::StructRef(name) => {
            if name.is_empty() {
                return Err(TemplateError::InvalidFieldReference(
                    "StructRef name cannot be empty".to_string(),
                ));
            }
        }
        super::FieldType::Array { element_type, .. } => {
            validate_field_type(element_type)?;
        }
        super::FieldType::Bitfield { backing_type, .. } => {
            validate_field_type(backing_type)?;
        }
        super::FieldType::Union { variants } => {
            for v in variants {
                validate_field_type(&v.field_type)?;
            }
        }
        super::FieldType::Enum { backing_type, .. } => {
            validate_field_type(backing_type)?;
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
        let json = r#"{"name": "", "description": "", "default_endianness": "little", "fields": []}"#;
        let result = parse_json_template(json);
        assert!(result.is_err());
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
}
