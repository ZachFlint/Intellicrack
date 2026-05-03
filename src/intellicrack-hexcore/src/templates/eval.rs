use std::collections::HashMap;

use super::{
    field_size, format_field_value, read_numeric_value, ConditionOp, Endianness, FieldDefinition,
    FieldType, FieldValidation, ParsedField, StructTemplate, TemplateError, TemplateRegistry,
};

const MAX_DEPTH: usize = 16;

pub struct TemplateEvaluator<'a> {
    data: &'a [u8],
    current_offset: usize,
    base_offset: usize,
    default_endian: Endianness,
    parsed_values: HashMap<String, i64>,
    registry: &'a TemplateRegistry,
    depth: usize,
}

impl<'a> TemplateEvaluator<'a> {
    #[must_use]
    pub fn new(
        data: &'a [u8],
        base_offset: usize,
        default_endian: Endianness,
        registry: &'a TemplateRegistry,
    ) -> Self {
        Self {
            data,
            current_offset: base_offset,
            base_offset,
            default_endian,
            parsed_values: HashMap::new(),
            registry,
            depth: 0,
        }
    }

    /// Evaluate a slice of field definitions against the binary data.
    ///
    /// # Errors
    ///
    /// Returns `TemplateError` if evaluation fails due to insufficient data,
    /// invalid field references, expression errors, or circular references.
    pub fn evaluate_fields(
        &mut self,
        fields: &[FieldDefinition],
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let mut results = Vec::new();
        for field in fields {
            let parsed = self.evaluate_field(field)?;
            results.extend(parsed);
        }
        Ok(results)
    }

    fn evaluate_field(
        &mut self,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let endian = field.endianness.unwrap_or(self.default_endian);

        match &field.field_type {
            FieldType::DynamicArray {
                element_type,
                count_field,
            } => self.eval_dynamic_array(&field.name, element_type, count_field, endian, field),

            FieldType::Conditional {
                condition_field,
                condition_value,
                condition_op,
                fields,
            } => self.eval_conditional(condition_field, *condition_value, *condition_op, fields),

            FieldType::StructRef(template_name) => {
                self.eval_struct_ref(&field.name, template_name, field)
            }

            FieldType::Pointer {
                pointer_type,
                target_template,
            } => self.eval_pointer(&field.name, pointer_type, target_template, endian, field),

            FieldType::Union { variants } => self.eval_union(&field.name, variants, field),

            FieldType::Enum {
                backing_type,
                values,
            } => self.eval_enum(&field.name, backing_type, values, endian, field),

            FieldType::Bitfield {
                bit_width,
                backing_type,
                flags,
            } => self.eval_bitfield(
                &field.name,
                *bit_width,
                backing_type,
                flags.as_deref(),
                endian,
                field,
            ),

            FieldType::Computed {
                expression,
                display_type,
            } => self.eval_computed(&field.name, expression, display_type, field),

            FieldType::EndiannessSwitch {
                peek_offset,
                big_value,
            } => self.eval_endianness_switch(&field.name, *peek_offset, *big_value, field),

            _ => {
                let size = field_size(&field.field_type);
                if self.current_offset + size > self.data.len() {
                    return Err(TemplateError::InsufficientData {
                        offset: self.current_offset,
                        needed: size,
                        available: self.data.len().saturating_sub(self.current_offset),
                    });
                }

                let raw = self.data[self.current_offset..self.current_offset + size].to_vec();
                let display = format_field_value(&field.field_type, &raw, endian);

                let numeric = read_numeric_value(&field.field_type, &raw, endian);
                self.parsed_values.insert(field.name.clone(), numeric);

                let validation_passed = field
                    .validation
                    .as_ref()
                    .map(|v| check_validation(v, numeric, &raw));

                let children = self.eval_array_children(&field.field_type, endian);

                let parsed = ParsedField {
                    name: field.name.clone(),
                    offset: self.current_offset,
                    size,
                    raw_bytes: raw,
                    display_value: display,
                    children,
                    color: field.color.clone(),
                    validation_passed,
                    description: field.description.clone(),
                };

                self.current_offset += size;
                Ok(vec![parsed])
            }
        }
    }

    fn eval_array_children(&self, ft: &FieldType, endian: Endianness) -> Vec<ParsedField> {
        if let FieldType::Array {
            element_type,
            count,
        } = ft
        {
            let inner_size = field_size(element_type);
            let mut children = Vec::new();
            for i in 0..*count {
                let arr_offset = self.current_offset + i * inner_size;
                if arr_offset + inner_size > self.data.len() {
                    break;
                }
                let arr_raw = self.data[arr_offset..arr_offset + inner_size].to_vec();
                let arr_display = format_field_value(element_type, &arr_raw, endian);
                children.push(ParsedField {
                    name: format!("[{i}]"),
                    offset: arr_offset,
                    size: inner_size,
                    raw_bytes: arr_raw,
                    display_value: arr_display,
                    children: Vec::new(),
                    color: None,
                    validation_passed: None,
                    description: String::new(),
                });
            }
            children
        } else {
            Vec::new()
        }
    }

    fn eval_dynamic_array(
        &mut self,
        name: &str,
        element_type: &FieldType,
        count_field: &str,
        endian: Endianness,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let count_raw = self
            .parsed_values
            .get(count_field)
            .copied()
            .ok_or_else(|| {
                TemplateError::InvalidFieldReference(format!(
                    "count_field '{count_field}' not found in parsed values"
                ))
            })?;

        let count = usize::try_from(count_raw.max(0))
            .map_err(|e| TemplateError::ExpressionError(format!("count overflow: {e}")))?;
        let inner_size = field_size(element_type);
        let total_size = inner_size * count;

        if self.current_offset + total_size > self.data.len() {
            return Err(TemplateError::InsufficientData {
                offset: self.current_offset,
                needed: total_size,
                available: self.data.len().saturating_sub(self.current_offset),
            });
        }

        let raw = self.data[self.current_offset..self.current_offset + total_size].to_vec();
        let mut children = Vec::new();

        for i in 0..count {
            let arr_offset = self.current_offset + i * inner_size;
            let arr_raw = self.data[arr_offset..arr_offset + inner_size].to_vec();
            let arr_display = format_field_value(element_type, &arr_raw, endian);
            children.push(ParsedField {
                name: format!("[{i}]"),
                offset: arr_offset,
                size: inner_size,
                raw_bytes: arr_raw,
                display_value: arr_display,
                children: Vec::new(),
                color: None,
                validation_passed: None,
                description: String::new(),
            });
        }

        let parsed = ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size: total_size,
            raw_bytes: raw,
            display_value: format!("[{count} x {}]", super::field_type_name(element_type)),
            children,
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        };

        self.current_offset += total_size;
        Ok(vec![parsed])
    }

    fn eval_conditional(
        &mut self,
        condition_field: &str,
        condition_value: i64,
        condition_op: ConditionOp,
        fields: &[FieldDefinition],
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let actual = self
            .parsed_values
            .get(condition_field)
            .copied()
            .ok_or_else(|| {
                TemplateError::InvalidFieldReference(format!(
                    "condition_field '{condition_field}' not found"
                ))
            })?;

        let condition_met = match condition_op {
            ConditionOp::Eq => actual == condition_value,
            ConditionOp::Ne => actual != condition_value,
            ConditionOp::Gt => actual > condition_value,
            ConditionOp::Lt => actual < condition_value,
            ConditionOp::Ge => actual >= condition_value,
            ConditionOp::Le => actual <= condition_value,
            ConditionOp::BitAnd => (actual & condition_value) != 0,
            ConditionOp::BitAndZero => (actual & condition_value) == 0,
        };

        if condition_met {
            self.evaluate_fields(fields)
        } else {
            Ok(Vec::new())
        }
    }

    fn eval_struct_ref(
        &mut self,
        name: &str,
        template_name: &str,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        if self.depth >= MAX_DEPTH {
            return Err(TemplateError::CircularReference(format!(
                "max nesting depth {MAX_DEPTH} exceeded for '{template_name}'"
            )));
        }

        let template = self
            .registry
            .get(template_name)
            .ok_or_else(|| TemplateError::NotFound(template_name.to_string()))?;

        let saved_endian = self.default_endian;
        let saved_base = self.base_offset;
        self.default_endian = template.default_endianness;
        self.base_offset = self.current_offset;
        self.depth += 1;

        let start_offset = self.current_offset;
        let children = self.evaluate_fields(&template.fields)?;
        let end_offset = self.current_offset;

        self.depth -= 1;
        self.default_endian = saved_endian;
        self.base_offset = saved_base;

        let size = end_offset - start_offset;
        let raw = if start_offset + size <= self.data.len() {
            self.data[start_offset..start_offset + size].to_vec()
        } else {
            Vec::new()
        };

        Ok(vec![ParsedField {
            name: name.to_string(),
            offset: start_offset,
            size,
            raw_bytes: raw,
            display_value: format!("struct {template_name}"),
            children,
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        }])
    }

    fn eval_pointer(
        &mut self,
        name: &str,
        pointer_type: &FieldType,
        target_template: &str,
        endian: Endianness,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let ptr_size = field_size(pointer_type);
        if self.current_offset + ptr_size > self.data.len() {
            return Err(TemplateError::InsufficientData {
                offset: self.current_offset,
                needed: ptr_size,
                available: self.data.len().saturating_sub(self.current_offset),
            });
        }

        let raw = self.data[self.current_offset..self.current_offset + ptr_size].to_vec();
        let ptr_numeric = read_numeric_value(pointer_type, &raw, endian);
        let ptr_value = usize::try_from(ptr_numeric).unwrap_or(0);
        let ptr_i64 = i64::try_from(ptr_value).unwrap_or(0);
        self.parsed_values.insert(name.to_string(), ptr_i64);

        let display = format!("-> 0x{ptr_value:X} ({target_template})");

        let children = if ptr_value < self.data.len() && self.depth < MAX_DEPTH {
            if let Some(template) = self.registry.get(target_template) {
                let saved_offset = self.current_offset;
                let saved_endian = self.default_endian;
                let saved_base = self.base_offset;
                self.current_offset = ptr_value;
                self.default_endian = template.default_endianness;
                self.base_offset = ptr_value;
                self.depth += 1;
                let result = self.evaluate_fields(&template.fields);
                self.depth -= 1;
                self.current_offset = saved_offset;
                self.default_endian = saved_endian;
                self.base_offset = saved_base;
                result?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let parsed = ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size: ptr_size,
            raw_bytes: raw,
            display_value: display,
            children,
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        };

        self.current_offset += ptr_size;
        Ok(vec![parsed])
    }

    fn eval_union(
        &mut self,
        name: &str,
        variants: &[FieldDefinition],
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let start = self.current_offset;
        let mut max_size: usize = 0;
        let mut all_children = Vec::new();

        for variant in variants {
            self.current_offset = start;
            let children = self.evaluate_field(variant)?;
            let variant_end = self.current_offset;
            let variant_size = variant_end - start;
            if variant_size > max_size {
                max_size = variant_size;
            }
            all_children.extend(children);
        }

        self.current_offset = start + max_size;

        let raw = if start + max_size <= self.data.len() {
            self.data[start..start + max_size].to_vec()
        } else {
            Vec::new()
        };

        Ok(vec![ParsedField {
            name: name.to_string(),
            offset: start,
            size: max_size,
            raw_bytes: raw,
            display_value: format!("union<{} variants>", variants.len()),
            children: all_children,
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        }])
    }

    fn eval_enum(
        &mut self,
        name: &str,
        backing_type: &FieldType,
        values: &[(String, i64)],
        endian: Endianness,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let size = field_size(backing_type);
        if self.current_offset + size > self.data.len() {
            return Err(TemplateError::InsufficientData {
                offset: self.current_offset,
                needed: size,
                available: self.data.len().saturating_sub(self.current_offset),
            });
        }

        let raw = self.data[self.current_offset..self.current_offset + size].to_vec();
        let numeric = read_numeric_value(backing_type, &raw, endian);
        self.parsed_values.insert(name.to_string(), numeric);

        let variant_name = values
            .iter()
            .find(|(_, v)| *v == numeric)
            .map_or("unknown", |(n, _)| n.as_str());

        let display = format!("{variant_name} ({numeric}, 0x{numeric:X})");

        let parsed = ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size,
            raw_bytes: raw.clone(),
            display_value: display,
            children: Vec::new(),
            color: field.color.clone(),
            validation_passed: field
                .validation
                .as_ref()
                .map(|v| check_validation(v, numeric, &raw)),
            description: field.description.clone(),
        };

        self.current_offset += size;
        Ok(vec![parsed])
    }

    fn eval_bitfield(
        &mut self,
        name: &str,
        bit_width: u8,
        backing_type: &FieldType,
        flags: Option<&[(String, u64)]>,
        endian: Endianness,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let size = field_size(backing_type);
        if self.current_offset + size > self.data.len() {
            return Err(TemplateError::InsufficientData {
                offset: self.current_offset,
                needed: size,
                available: self.data.len().saturating_sub(self.current_offset),
            });
        }

        let raw = self.data[self.current_offset..self.current_offset + size].to_vec();
        let numeric = read_numeric_value(backing_type, &raw, endian);
        let mask = if bit_width >= 64 {
            u64::MAX
        } else {
            (1u64 << bit_width) - 1
        };
        let numeric_bits = u64::from_ne_bytes(numeric.to_ne_bytes());
        let masked = numeric_bits & mask;
        self.parsed_values
            .insert(name.to_string(), i64::from_ne_bytes(masked.to_ne_bytes()));

        let mut children = Vec::new();
        if let Some(flag_list) = flags {
            for (flag_name, flag_value) in flag_list {
                let is_set = (masked & flag_value) != 0;
                children.push(ParsedField {
                    name: flag_name.clone(),
                    offset: self.current_offset,
                    size: 0,
                    raw_bytes: Vec::new(),
                    display_value: if is_set {
                        format!("SET (0x{flag_value:X})")
                    } else {
                        format!("CLEAR (0x{flag_value:X})")
                    },
                    children: Vec::new(),
                    color: None,
                    validation_passed: None,
                    description: String::new(),
                });
            }
        }

        let bits = size * 8;
        let display = format!("0x{masked:X} ({bit_width}:{bits} bits)");

        let parsed = ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size,
            raw_bytes: raw,
            display_value: display,
            children,
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        };

        self.current_offset += size;
        Ok(vec![parsed])
    }

    fn eval_computed(
        &mut self,
        name: &str,
        expression: &str,
        display_type: &FieldType,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let value = evaluate_expression(
            expression,
            &self.parsed_values,
            self.current_offset,
            self.registry,
        )?;
        self.parsed_values.insert(name.to_string(), value);

        let value_hex = u64::from_ne_bytes(value.to_ne_bytes());
        let display = format!("{value} (0x{value_hex:X}) = {expression}");

        Ok(vec![ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size: 0,
            raw_bytes: Vec::new(),
            display_value: display,
            children: Vec::new(),
            color: field.color.clone(),
            validation_passed: None,
            description: format!(
                "{} [computed as {}]",
                field.description,
                super::field_type_name(display_type)
            ),
        }])
    }

    fn eval_endianness_switch(
        &mut self,
        name: &str,
        peek_offset: usize,
        big_value: u8,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let peek_abs = self.base_offset.saturating_add(peek_offset);
        if peek_abs >= self.data.len() {
            return Err(TemplateError::InsufficientData {
                offset: peek_abs,
                needed: 1,
                available: self.data.len().saturating_sub(peek_abs),
            });
        }

        let peek_byte = self.data[peek_abs];
        self.default_endian = if peek_byte == big_value {
            Endianness::Big
        } else {
            Endianness::Little
        };

        let endian_label = match self.default_endian {
            Endianness::Little => "little",
            Endianness::Big => "big",
        };
        let display = format!(
            "{endian_label} (peek[base+{peek_offset}]=0x{peek_byte:02X}, big_value=0x{big_value:02X})"
        );

        Ok(vec![ParsedField {
            name: name.to_string(),
            offset: peek_abs,
            size: 0,
            raw_bytes: vec![peek_byte],
            display_value: display,
            children: Vec::new(),
            color: field.color.clone(),
            validation_passed: None,
            description: field.description.clone(),
        }])
    }
}

fn check_validation(validation: &FieldValidation, numeric: i64, raw: &[u8]) -> bool {
    if let Some(expected) = validation.expected_value {
        if numeric != expected {
            return false;
        }
    }
    if let Some(min) = validation.min_value {
        if numeric < min {
            return false;
        }
    }
    if let Some(max) = validation.max_value {
        if numeric > max {
            return false;
        }
    }
    if let Some(magic) = &validation.magic_bytes {
        if raw.len() < magic.len() || &raw[..magic.len()] != magic.as_slice() {
            return false;
        }
    }
    true
}

fn evaluate_expression(
    expr: &str,
    values: &HashMap<String, i64>,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i64, TemplateError> {
    let tokens = tokenize_expr(expr)?;
    let mut pos = 0;
    let result = parse_additive(&tokens, &mut pos, values, current_offset, registry)?;
    Ok(result)
}

/// Resolve `sizeof(<type_name>)` to a concrete byte count.
///
/// Tries the built-in primitive table first (matching the names already
/// accepted by template field types). Falls back to the supplied
/// `TemplateRegistry`, summing the size of each field of a registered
/// struct template. Errors with [`TemplateError::UnknownType`] when the
/// name matches neither — replacing the previous silent zero return that
/// allowed typos like `sizeof(uint128)` to collapse expressions to 0.
fn resolve_sizeof(type_name: &str, registry: &TemplateRegistry) -> Result<usize, TemplateError> {
    let primitive = match type_name {
        "u8" | "uint8" | "int8" | "s8" | "bool" | "char" => Some(1usize),
        "u16" | "uint16" | "int16" | "s16" => Some(2),
        "u32" | "uint32" | "int32" | "s32" | "float" | "float32" => Some(4),
        "u64" | "uint64" | "int64" | "s64" | "double" | "float64" => Some(8),
        _ => None,
    };
    if let Some(size) = primitive {
        return Ok(size);
    }
    if let Some(template) = registry.get(type_name) {
        return struct_template_size(type_name, template);
    }
    Err(TemplateError::UnknownType(type_name.to_string()))
}

/// Compute the byte size of a registered struct template by summing the
/// fixed-size cost of each field.
///
/// Returns `Err(TemplateError::UnknownType)` if the template contains a
/// field whose size depends on runtime data (dynamic arrays, unions,
/// conditionals, struct refs, computed, endianness switch). Those cases
/// have no statically computable size and `sizeof()` cannot meaningfully
/// stand in for them inside an arithmetic expression.
fn struct_template_size(
    template_name: &str,
    template: &StructTemplate,
) -> Result<usize, TemplateError> {
    let mut total: usize = 0;
    for field in &template.fields {
        let size = field_size(&field.field_type);
        if size == 0 && !is_zero_size_type(&field.field_type) {
            return Err(TemplateError::UnknownType(format!(
                "{template_name} (field '{}' has runtime-dependent size)",
                field.name
            )));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| TemplateError::UnknownType(template_name.to_string()))?;
    }
    Ok(total)
}

/// Return `true` for `FieldType` variants that are legitimately zero
/// bytes (e.g. zero-length padding) so a `field_size` of zero is not
/// confused with a runtime-dependent type.
fn is_zero_size_type(ft: &FieldType) -> bool {
    matches!(
        ft,
        FieldType::Bytes(0) | FieldType::FixedString(0) | FieldType::Padding(0),
    )
}

#[derive(Debug, Clone)]
enum ExprToken {
    Number(i64),
    Ident(String),
    Dollar,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    LParen,
    RParen,
    Sizeof,
}

fn tokenize_expr(expr: &str) -> Result<Vec<ExprToken>, TemplateError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '$' => {
                tokens.push(ExprToken::Dollar);
                i += 1;
            }
            '+' => {
                tokens.push(ExprToken::Plus);
                i += 1;
            }
            '-' => {
                tokens.push(ExprToken::Minus);
                i += 1;
            }
            '*' => {
                tokens.push(ExprToken::Star);
                i += 1;
            }
            '/' => {
                tokens.push(ExprToken::Slash);
                i += 1;
            }
            '%' => {
                tokens.push(ExprToken::Percent);
                i += 1;
            }
            '(' => {
                tokens.push(ExprToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(ExprToken::RParen);
                i += 1;
            }
            '0'..='9' => {
                let start = i;
                if i + 1 < chars.len()
                    && chars[i] == '0'
                    && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
                {
                    i += 2;
                    while i < chars.len() && chars[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                    let hex_str: String = chars[start + 2..i].iter().collect();
                    let val = i64::from_str_radix(&hex_str, 16)
                        .map_err(|e| TemplateError::ExpressionError(format!("bad hex: {e}")))?;
                    tokens.push(ExprToken::Number(val));
                } else {
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    let num_str: String = chars[start..i].iter().collect();
                    let val: i64 = num_str
                        .parse()
                        .map_err(|e| TemplateError::ExpressionError(format!("bad number: {e}")))?;
                    tokens.push(ExprToken::Number(val));
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                if ident == "sizeof" {
                    tokens.push(ExprToken::Sizeof);
                } else {
                    tokens.push(ExprToken::Ident(ident));
                }
            }
            c => {
                return Err(TemplateError::ExpressionError(format!(
                    "unexpected character '{c}'"
                )));
            }
        }
    }

    Ok(tokens)
}

fn parse_additive(
    tokens: &[ExprToken],
    pos: &mut usize,
    values: &HashMap<String, i64>,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i64, TemplateError> {
    let mut left = parse_multiplicative(tokens, pos, values, current_offset, registry)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            ExprToken::Plus => {
                *pos += 1;
                let right = parse_multiplicative(tokens, pos, values, current_offset, registry)?;
                left = left.wrapping_add(right);
            }
            ExprToken::Minus => {
                *pos += 1;
                let right = parse_multiplicative(tokens, pos, values, current_offset, registry)?;
                left = left.wrapping_sub(right);
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_multiplicative(
    tokens: &[ExprToken],
    pos: &mut usize,
    values: &HashMap<String, i64>,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i64, TemplateError> {
    let mut left = parse_unary(tokens, pos, values, current_offset, registry)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            ExprToken::Star => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry)?;
                left = left.wrapping_mul(right);
            }
            ExprToken::Slash => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry)?;
                if right == 0 {
                    return Err(TemplateError::ExpressionError(
                        "division by zero".to_string(),
                    ));
                }
                left = left.wrapping_div(right);
            }
            ExprToken::Percent => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry)?;
                if right == 0 {
                    return Err(TemplateError::ExpressionError("modulo by zero".to_string()));
                }
                left = left.wrapping_rem(right);
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_unary(
    tokens: &[ExprToken],
    pos: &mut usize,
    values: &HashMap<String, i64>,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i64, TemplateError> {
    if *pos < tokens.len() {
        if let ExprToken::Minus = &tokens[*pos] {
            *pos += 1;
            let val = parse_primary(tokens, pos, values, current_offset, registry)?;
            return Ok(-val);
        }
    }
    parse_primary(tokens, pos, values, current_offset, registry)
}

fn parse_primary(
    tokens: &[ExprToken],
    pos: &mut usize,
    values: &HashMap<String, i64>,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i64, TemplateError> {
    if *pos >= tokens.len() {
        return Err(TemplateError::ExpressionError(
            "unexpected end of expression".to_string(),
        ));
    }

    match &tokens[*pos] {
        ExprToken::Number(n) => {
            let val = *n;
            *pos += 1;
            Ok(val)
        }
        ExprToken::Dollar => {
            *pos += 1;
            i64::try_from(current_offset)
                .map_err(|e| TemplateError::ExpressionError(format!("offset overflow: {e}")))
        }
        ExprToken::Ident(name) => {
            let val = values.get(name).copied().ok_or_else(|| {
                TemplateError::InvalidFieldReference(format!(
                    "field '{name}' not found in expression"
                ))
            })?;
            *pos += 1;
            Ok(val)
        }
        ExprToken::Sizeof => {
            *pos += 1;
            if *pos < tokens.len() {
                if let ExprToken::LParen = &tokens[*pos] {
                    *pos += 1;
                    if *pos < tokens.len() {
                        if let ExprToken::Ident(name) = &tokens[*pos] {
                            let type_name = name.clone();
                            *pos += 1;
                            if *pos < tokens.len() {
                                if let ExprToken::RParen = &tokens[*pos] {
                                    *pos += 1;
                                }
                            }
                            let size = resolve_sizeof(&type_name, registry)?;
                            let size_i64 = i64::try_from(size).map_err(|e| {
                                TemplateError::ExpressionError(format!("sizeof overflow: {e}"))
                            })?;
                            return Ok(size_i64);
                        }
                    }
                }
            }
            Err(TemplateError::ExpressionError(
                "invalid sizeof syntax".to_string(),
            ))
        }
        ExprToken::LParen => {
            *pos += 1;
            let val = parse_additive(tokens, pos, values, current_offset, registry)?;
            if *pos < tokens.len() {
                if let ExprToken::RParen = &tokens[*pos] {
                    *pos += 1;
                }
            }
            Ok(val)
        }
        other => Err(TemplateError::ExpressionError(format!(
            "unexpected token: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::{FieldDefinition, FieldType};

    fn make_registry() -> TemplateRegistry {
        TemplateRegistry::new()
    }

    #[test]
    fn test_basic_eval() {
        let reg = make_registry();
        let fields = vec![
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
        ];
        let data = [0x42, 0x34, 0x12];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "a");
        assert_eq!(result[1].name, "b");
    }

    #[test]
    fn test_dynamic_array() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                name: "count".to_string(),
                field_type: FieldType::UInt8,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "items".to_string(),
                field_type: FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "count".to_string(),
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        let data = [0x03, 0xAA, 0xBB, 0xCC];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].children.len(), 3);
    }

    #[test]
    fn test_conditional_true() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                name: "magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "magic".to_string(),
                    condition_value: 0x5A4D,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        name: "pe_field".to_string(),
                        field_type: FieldType::UInt32,
                        endianness: None,
                        description: String::new(),
                        color: None,
                        validation: None,
                    }],
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        let data = [0x4D, 0x5A, 0x01, 0x02, 0x03, 0x04];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].name, "pe_field");
    }

    #[test]
    fn test_conditional_false() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                name: "magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "magic".to_string(),
                    condition_value: 0xFFFF,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        name: "pe_field".to_string(),
                        field_type: FieldType::UInt32,
                        endianness: None,
                        description: String::new(),
                        color: None,
                        validation: None,
                    }],
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        let data = [0x4D, 0x5A, 0x01, 0x02, 0x03, 0x04];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 1);
    }

    fn make_bitmask_fields(
        condition_op: ConditionOp,
        condition_value: i64,
    ) -> Vec<FieldDefinition> {
        vec![
            FieldDefinition {
                name: "flags".to_string(),
                field_type: FieldType::UInt8,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "flags".to_string(),
                    condition_value,
                    condition_op,
                    fields: vec![FieldDefinition {
                        name: "guarded".to_string(),
                        field_type: FieldType::UInt8,
                        endianness: None,
                        description: String::new(),
                        color: None,
                        validation: None,
                    }],
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ]
    }

    #[test]
    fn test_conditional_bitand_set_emits_inner() {
        let reg = make_registry();
        let fields = make_bitmask_fields(ConditionOp::BitAnd, 0b0000_0100);
        let data = [0b0000_0110, 0xAA];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].name, "guarded");
    }

    #[test]
    fn test_conditional_bitand_clear_skips_inner() {
        let reg = make_registry();
        let fields = make_bitmask_fields(ConditionOp::BitAnd, 0b0000_0100);
        let data = [0b0000_0010, 0xAA];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_conditional_bitand_zero_clear_emits_inner() {
        let reg = make_registry();
        let fields = make_bitmask_fields(ConditionOp::BitAndZero, 0b0000_0100);
        let data = [0b0000_0010, 0xAA];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].name, "guarded");
    }

    #[test]
    fn test_conditional_bitand_zero_set_skips_inner() {
        let reg = make_registry();
        let fields = make_bitmask_fields(ConditionOp::BitAndZero, 0b0000_0100);
        let data = [0b0000_0110, 0xAA];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_enum_field() {
        let reg = make_registry();
        let fields = vec![FieldDefinition {
            name: "file_type".to_string(),
            field_type: FieldType::Enum {
                backing_type: Box::new(FieldType::UInt16),
                values: vec![
                    ("EXEC".to_string(), 2),
                    ("DYN".to_string(), 3),
                    ("CORE".to_string(), 4),
                ],
            },
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }];
        let data = [0x02, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert!(result[0].display_value.contains("EXEC"));
    }

    #[test]
    fn test_validation_pass() {
        let reg = make_registry();
        let fields = vec![FieldDefinition {
            name: "magic".to_string(),
            field_type: FieldType::UInt16,
            endianness: None,
            description: String::new(),
            color: None,
            validation: Some(FieldValidation {
                expected_value: Some(0x5A4D),
                min_value: None,
                max_value: None,
                magic_bytes: None,
            }),
        }];
        let data = [0x4D, 0x5A];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].validation_passed, Some(true));
    }

    #[test]
    fn test_validation_fail() {
        let reg = make_registry();
        let fields = vec![FieldDefinition {
            name: "magic".to_string(),
            field_type: FieldType::UInt16,
            endianness: None,
            description: String::new(),
            color: None,
            validation: Some(FieldValidation {
                expected_value: Some(0x5A4D),
                min_value: None,
                max_value: None,
                magic_bytes: None,
            }),
        }];
        let data = [0x00, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].validation_passed, Some(false));
    }

    #[test]
    fn test_expression_eval() {
        let reg = make_registry();
        let mut values = HashMap::new();
        values.insert("a".to_string(), 10);
        values.insert("b".to_string(), 3);
        assert_eq!(evaluate_expression("a + b", &values, 0, &reg).unwrap(), 13);
        assert_eq!(evaluate_expression("a * b", &values, 0, &reg).unwrap(), 30);
        assert_eq!(evaluate_expression("a - b", &values, 0, &reg).unwrap(), 7);
        assert_eq!(
            evaluate_expression("(a + b) * 2", &values, 0, &reg).unwrap(),
            26
        );
        assert_eq!(
            evaluate_expression("$", &values, 0x100, &reg).unwrap(),
            0x100
        );
    }

    #[test]
    fn test_bool_char_padding() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                name: "flag".to_string(),
                field_type: FieldType::Bool,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "letter".to_string(),
                field_type: FieldType::Char,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                name: "pad".to_string(),
                field_type: FieldType::Padding(2),
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        let data = [0x01, 0x41, 0x00, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].display_value, "true");
        assert!(result[1].display_value.contains("'A'"));
        assert!(result[2].display_value.contains("padding"));
    }

    /// Audit-1 F-0005 regression: `sizeof(<unknown>)` must produce a
    /// `TemplateError::UnknownType` rather than silently returning 0.
    #[test]
    fn test_sizeof_unknown_type_errors() {
        let reg = make_registry();
        let values = HashMap::new();
        let err = evaluate_expression("sizeof(uint128)", &values, 0, &reg)
            .expect_err("sizeof of unknown type must fail");
        match err {
            TemplateError::UnknownType(name) => assert_eq!(name, "uint128"),
            other => panic!("expected UnknownType, got {other:?}"),
        }
    }

    /// Audit-1 F-0005 regression: `sizeof(<typo struct ref>)` must
    /// produce `UnknownType` because the typo'd name is not registered.
    #[test]
    fn test_sizeof_typo_struct_ref_errors() {
        let reg = make_registry();
        let values = HashMap::new();
        let err = evaluate_expression("sizeof(SomeStruct)", &values, 0, &reg)
            .expect_err("sizeof of unregistered struct must fail");
        assert!(matches!(err, TemplateError::UnknownType(_)));
    }

    /// Audit-1 F-0005 happy-path: primitive type names continue to
    /// resolve without registry lookup.
    #[test]
    fn test_sizeof_primitives_still_resolve() {
        let reg = make_registry();
        let values = HashMap::new();
        assert_eq!(
            evaluate_expression("sizeof(u8)", &values, 0, &reg).unwrap(),
            1
        );
        assert_eq!(
            evaluate_expression("sizeof(uint16)", &values, 0, &reg).unwrap(),
            2
        );
        assert_eq!(
            evaluate_expression("sizeof(u32)", &values, 0, &reg).unwrap(),
            4
        );
        assert_eq!(
            evaluate_expression("sizeof(double)", &values, 0, &reg).unwrap(),
            8
        );
    }

    /// Audit-1 F-0005 happy-path: registered fixed-size struct templates
    /// resolve via `TemplateRegistry`.
    #[test]
    fn test_sizeof_registered_struct_resolves() {
        let mut reg = make_registry();
        let template = StructTemplate {
            name: "Header".to_string(),
            description: String::new(),
            fields: vec![
                FieldDefinition {
                    name: "magic".to_string(),
                    field_type: FieldType::UInt32,
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    name: "version".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    name: "pad".to_string(),
                    field_type: FieldType::Padding(2),
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
            ],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        };
        reg.register(template);
        let values = HashMap::new();
        assert_eq!(
            evaluate_expression("sizeof(Header)", &values, 0, &reg).unwrap(),
            8,
        );
    }

    /// Audit-1 F-0004 regression: a `Pointer` field whose target template
    /// errors during recursive evaluation must propagate the error rather
    /// than swallow it via `unwrap_or_default()`.
    #[test]
    fn test_eval_pointer_propagates_recursive_error() {
        let mut reg = TemplateRegistry::new();
        let target = StructTemplate {
            name: "Bad".to_string(),
            description: String::new(),
            fields: vec![FieldDefinition {
                name: "ref_to_missing".to_string(),
                field_type: FieldType::Computed {
                    expression: "missing_field + 1".to_string(),
                    display_type: Box::new(FieldType::UInt32),
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            }],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        };
        reg.register(target);
        let outer = vec![FieldDefinition {
            name: "ptr".to_string(),
            field_type: FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt32),
                target_template: "Bad".to_string(),
            },
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }];
        let mut data = vec![0u8; 32];
        data[..4].copy_from_slice(&8u32.to_le_bytes());
        let mut evaluator = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = evaluator
            .evaluate_fields(&outer)
            .expect_err("pointer must propagate recursive evaluation errors");
        assert!(matches!(err, TemplateError::InvalidFieldReference(_)));
    }
}
