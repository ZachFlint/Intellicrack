// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::{
    field_size, float_to_i64_saturating, format_field_value, low_64_bits, read_numeric_value,
    read_scalar_value, ConditionOp, Endianness, FieldDefinition, FieldType, FieldValidation,
    ParsedField, ScalarValue, StructTemplate, TemplateError, TemplateRegistry,
};

const MAX_DEPTH: usize = 16;

const MAX_EVALUATED_FIELDS: usize = 1 << 20;

const MAX_ARRAY_CHILDREN: usize = 65_536;

/// The field-count limit bounds how many fields are produced, but a single
/// pointer or struct reference re-copies every byte it covers into its
/// `raw_bytes`, so a template that fans many references at one large region
/// can multiply a small file into gigabytes of parsed output. Evaluation may
/// copy at most `OUTPUT_BYTES_PER_INPUT_BYTE` bytes for each input byte, plus a
/// fixed floor, before it is aborted with `ResourceLimit`.
const OUTPUT_BYTES_PER_INPUT_BYTE: usize = 64;

const OUTPUT_BYTE_FLOOR: usize = 1 << 20;

struct ValueScopes {
    layers: Vec<HashMap<String, i128>>,
}

impl ValueScopes {
    fn new() -> Self {
        Self {
            layers: vec![HashMap::new()],
        }
    }

    fn get(&self, name: &str) -> Option<i128> {
        self.layers
            .iter()
            .rev()
            .find_map(|layer| layer.get(name).copied())
    }

    fn insert(&mut self, name: String, value: i128) {
        if let Some(layer) = self.layers.last_mut() {
            layer.insert(name, value);
        }
    }

    fn push(&mut self) {
        self.layers.push(HashMap::new());
    }

    fn pop(&mut self) {
        if self.layers.len() > 1 {
            self.layers.pop();
        }
    }
}

/// Evaluates a template's fields against a byte buffer, tracking the current
/// offset, the active endianness and the named values earlier fields produced.
pub struct TemplateEvaluator<'a> {
    data: &'a [u8],
    current_offset: usize,
    base_offset: usize,
    default_endian: Endianness,
    values: ValueScopes,
    registry: &'a TemplateRegistry,
    depth: usize,
    evaluated_fields: usize,
    copied_bytes: usize,
    output_budget: usize,
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
            values: ValueScopes::new(),
            registry,
            depth: 0,
            evaluated_fields: 0,
            copied_bytes: 0,
            output_budget: data
                .len()
                .saturating_mul(OUTPUT_BYTES_PER_INPUT_BYTE)
                .saturating_add(OUTPUT_BYTE_FLOOR),
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

    fn charge(&mut self, count: usize) -> Result<(), TemplateError> {
        let total = self.evaluated_fields.saturating_add(count);
        if total > MAX_EVALUATED_FIELDS {
            return Err(TemplateError::ResourceLimit(format!(
                "template evaluation exceeds the limit of {MAX_EVALUATED_FIELDS} fields"
            )));
        }
        self.evaluated_fields = total;
        Ok(())
    }

    fn charge_bytes(&mut self, count: usize) -> Result<(), TemplateError> {
        let total = self.copied_bytes.saturating_add(count);
        if total > self.output_budget {
            return Err(TemplateError::ResourceLimit(format!(
                "template output exceeds the budget of {} copied bytes",
                self.output_budget
            )));
        }
        self.copied_bytes = total;
        Ok(())
    }

    fn copy_raw(&mut self, start: usize, len: usize) -> Result<Vec<u8>, TemplateError> {
        self.charge_bytes(len)?;
        Ok(self.data[start..start + len].to_vec())
    }

    /// The current offset relative to the enclosing struct's base: the value
    /// `$` takes in an expression, in the same frame `at` positions fields in.
    ///
    /// Fields only ever advance from the base, so the current offset is never
    /// below it.
    fn struct_position(&self) -> usize {
        self.current_offset.saturating_sub(self.base_offset)
    }

    fn ensure_available(&self, size: usize) -> Result<(), TemplateError> {
        if self
            .current_offset
            .checked_add(size)
            .is_none_or(|end| end > self.data.len())
        {
            return Err(TemplateError::InsufficientData {
                offset: self.current_offset,
                needed: size,
                available: self.data.len().saturating_sub(self.current_offset),
            });
        }
        Ok(())
    }

    fn evaluate_field(
        &mut self,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        self.charge(1)?;
        match &field.at {
            Some(expression) => self.evaluate_field_at(field, expression),
            None => self.evaluate_field_here(field),
        }
    }

    fn evaluate_field_at(
        &mut self,
        field: &FieldDefinition,
        expression: &str,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let relative = evaluate_expression(
            expression,
            &self.values,
            self.struct_position(),
            self.registry,
        )?;
        let relative = usize::try_from(relative).map_err(|_| {
            TemplateError::ExpressionError(format!(
                "field '{}' is positioned at the negative offset {relative}",
                field.name
            ))
        })?;
        let target = self.base_offset.checked_add(relative).ok_or_else(|| {
            TemplateError::ExpressionError(format!(
                "field '{}' is positioned at an offset that overflows",
                field.name
            ))
        })?;

        let resume = self.current_offset;
        self.current_offset = target;
        let result = self.evaluate_field_here(field);
        let end = self.current_offset;
        self.current_offset = if end > target {
            resume.max(end)
        } else {
            resume
        };
        result
    }

    fn evaluate_field_here(
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
                let size = field_size(&field.field_type).ok_or_else(|| {
                    TemplateError::UnsizedFieldType(format!(
                        "field '{}' has a type with no static size",
                        field.name
                    ))
                })?;
                self.ensure_available(size)?;

                let raw = self.copy_raw(self.current_offset, size)?;
                let mut display = format_field_value(&field.field_type, &raw, endian);

                let scalar = read_scalar_value(&field.field_type, &raw, endian);
                self.values.insert(field.name.clone(), scalar.to_integer());

                let validation_passed = field
                    .validation
                    .as_ref()
                    .map(|v| check_validation(v, scalar, &raw));

                let children = if let FieldType::Array {
                    element_type,
                    count,
                } = &field.field_type
                {
                    match field_size(element_type) {
                        Some(element_size) if element_size > 0 => {
                            display = with_truncation_note(display, *count);
                            self.element_children(
                                element_type,
                                element_size,
                                self.current_offset,
                                *count,
                                endian,
                            )?
                        }
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                };

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

    fn element_children(
        &mut self,
        element_type: &FieldType,
        element_size: usize,
        start: usize,
        count: usize,
        endian: Endianness,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let shown = count.min(MAX_ARRAY_CHILDREN);
        self.charge(shown)?;
        let mut children = Vec::with_capacity(shown);
        for i in 0..shown {
            let offset = start.saturating_add(i.saturating_mul(element_size));
            if offset.saturating_add(element_size) > self.data.len() {
                break;
            }
            let raw = self.copy_raw(offset, element_size)?;
            let display_value = format_field_value(element_type, &raw, endian);
            children.push(ParsedField {
                name: format!("[{i}]"),
                offset,
                size: element_size,
                raw_bytes: raw,
                display_value,
                children: Vec::new(),
                color: None,
                validation_passed: None,
                description: String::new(),
            });
        }
        Ok(children)
    }

    fn eval_dynamic_array(
        &mut self,
        name: &str,
        element_type: &FieldType,
        count_field: &str,
        endian: Endianness,
        field: &FieldDefinition,
    ) -> Result<Vec<ParsedField>, TemplateError> {
        let count_value = self.values.get(count_field).ok_or_else(|| {
            TemplateError::InvalidFieldReference(format!(
                "count_field '{count_field}' not found in parsed values"
            ))
        })?;

        let count = usize::try_from(count_value.max(0))
            .map_err(|e| TemplateError::ExpressionError(format!("count overflow: {e}")))?;
        let inner_size = field_size(element_type).ok_or_else(|| {
            TemplateError::UnsizedFieldType(format!(
                "DynamicArray '{name}' element_type has no static size"
            ))
        })?;
        if inner_size == 0 && count > 0 {
            return Err(TemplateError::UnsizedFieldType(format!(
                "DynamicArray '{name}' element_type is zero-sized; a count of {count} cannot be bounded by data length"
            )));
        }
        let total_size = inner_size.checked_mul(count).ok_or_else(|| {
            TemplateError::ExpressionError(format!("DynamicArray '{name}' size overflow"))
        })?;
        self.ensure_available(total_size)?;

        let raw = self.copy_raw(self.current_offset, total_size)?;
        let children =
            self.element_children(element_type, inner_size, self.current_offset, count, endian)?;

        let parsed = ParsedField {
            name: name.to_string(),
            offset: self.current_offset,
            size: total_size,
            raw_bytes: raw,
            display_value: with_truncation_note(
                format!("[{count} x {}]", super::field_type_name(element_type)),
                count,
            ),
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
        let actual = self.values.get(condition_field).ok_or_else(|| {
            TemplateError::InvalidFieldReference(format!(
                "condition_field '{condition_field}' not found"
            ))
        })?;

        let wanted = i128::from(condition_value);
        let condition_met = match condition_op {
            ConditionOp::Eq => actual == wanted,
            ConditionOp::Ne => actual != wanted,
            ConditionOp::Gt => actual > wanted,
            ConditionOp::Lt => actual < wanted,
            ConditionOp::Ge => actual >= wanted,
            ConditionOp::Le => actual <= wanted,
            ConditionOp::BitAnd => (low_64_bits(actual) & condition_value) != 0,
            ConditionOp::BitAndZero => (low_64_bits(actual) & condition_value) == 0,
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
        self.values.push();

        let start_offset = self.current_offset;
        let result = self.evaluate_fields(&template.fields);
        let end_offset = self.current_offset;

        self.values.pop();
        self.depth -= 1;
        self.default_endian = saved_endian;
        self.base_offset = saved_base;
        let children = result?;

        let size = end_offset - start_offset;
        let raw = if start_offset + size <= self.data.len() {
            self.copy_raw(start_offset, size)?
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
        let ptr_size = field_size(pointer_type).ok_or_else(|| {
            TemplateError::UnsizedFieldType(format!(
                "Pointer '{name}' pointer_type has no static size"
            ))
        })?;
        self.ensure_available(ptr_size)?;

        let raw = self.copy_raw(self.current_offset, ptr_size)?;
        let address = pointer_address(read_numeric_value(pointer_type, &raw, endian), ptr_size);
        self.values.insert(name.to_string(), i128::from(address));

        let display = format!("-> 0x{address:X} ({target_template})");

        let target = usize::try_from(address)
            .ok()
            .filter(|target| *target < self.data.len());
        let children = if let Some(target) = target {
            if self.depth >= MAX_DEPTH {
                return Err(TemplateError::CircularReference(format!(
                    "max nesting depth {MAX_DEPTH} exceeded for pointer '{name}' -> '{target_template}'"
                )));
            }
            if let Some(template) = self.registry.get(target_template) {
                let saved_offset = self.current_offset;
                let saved_endian = self.default_endian;
                let saved_base = self.base_offset;
                self.current_offset = target;
                self.default_endian = template.default_endianness;
                self.base_offset = target;
                self.depth += 1;
                self.values.push();
                let result = self.evaluate_fields(&template.fields);
                self.values.pop();
                self.depth -= 1;
                self.current_offset = saved_offset;
                self.default_endian = saved_endian;
                self.base_offset = saved_base;
                result?
            } else {
                return Err(TemplateError::NotFound(target_template.to_string()));
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
            self.copy_raw(start, max_size)?
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
        let size = field_size(backing_type).ok_or_else(|| {
            TemplateError::UnsizedFieldType(format!(
                "Enum '{name}' backing_type has no static size"
            ))
        })?;
        self.ensure_available(size)?;

        let raw = self.copy_raw(self.current_offset, size)?;
        let scalar = read_scalar_value(backing_type, &raw, endian);
        let numeric = scalar.to_integer();
        self.values.insert(name.to_string(), numeric);

        let variant_name = values
            .iter()
            .find(|(_, v)| enum_value_matches(numeric, *v, size))
            .map_or("unknown", |(n, _)| n.as_str());

        let hex = unsigned_at_width(numeric, size);
        let display = format!("{variant_name} ({numeric}, 0x{hex:X})");

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
                .map(|v| check_validation(v, scalar, &raw)),
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
        let size = field_size(backing_type).ok_or_else(|| {
            TemplateError::UnsizedFieldType(format!(
                "Bitfield '{name}' backing_type has no static size"
            ))
        })?;
        self.ensure_available(size)?;

        let raw = self.copy_raw(self.current_offset, size)?;
        let numeric = read_numeric_value(backing_type, &raw, endian);
        let mask = if bit_width >= 64 {
            u64::MAX
        } else {
            (1u64 << bit_width) - 1
        };
        let numeric_bits = u64::from_ne_bytes(low_64_bits(numeric).to_ne_bytes());
        let masked = numeric_bits & mask;
        self.values.insert(name.to_string(), i128::from(masked));

        let mut children = Vec::new();
        if let Some(flag_list) = flags {
            self.charge(flag_list.len())?;
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
            &self.values,
            self.struct_position(),
            self.registry,
        )?;
        self.values.insert(name.to_string(), value);

        let value_hex = u64::from_ne_bytes(low_64_bits(value).to_ne_bytes());
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

fn with_truncation_note(display: String, count: usize) -> String {
    if count > MAX_ARRAY_CHILDREN {
        format!("{display} (first {MAX_ARRAY_CHILDREN} elements shown)")
    } else {
        display
    }
}

fn pointer_address(value: i128, size: usize) -> u64 {
    let bits = u32::try_from(size.saturating_mul(8)).map_or(64, |bits| bits.min(64));
    let mask = match bits {
        0 => 0,
        64.. => u64::MAX,
        bits => (1u64 << bits) - 1,
    };
    u64::from_ne_bytes(low_64_bits(value).to_ne_bytes()) & mask
}

fn unsigned_at_width(value: i128, size: usize) -> u128 {
    let bits = u128::from_ne_bytes(value.to_ne_bytes());
    match u32::try_from(size.saturating_mul(8)) {
        Ok(width) if width < 128 => bits & ((1u128 << width) - 1),
        _ => bits,
    }
}

fn enum_value_matches(value: i128, variant: i64, size: usize) -> bool {
    value == i128::from(variant) || (size == 8 && low_64_bits(value) == variant)
}

fn compare_float_to_integer(value: f64, bound: i64) -> Option<Ordering> {
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if value.is_nan() {
        return None;
    }
    if value >= TWO_POW_63 {
        return Some(Ordering::Greater);
    }
    if value < -TWO_POW_63 {
        return Some(Ordering::Less);
    }
    let fraction = value.fract().partial_cmp(&0.0).unwrap_or(Ordering::Equal);
    Some(float_to_i64_saturating(value).cmp(&bound).then(fraction))
}

fn check_validation(validation: &FieldValidation, value: ScalarValue, raw: &[u8]) -> bool {
    let numeric_checks_hold = match value {
        ScalarValue::Integer(v) => {
            validation.expected_value.is_none_or(|e| v == i128::from(e))
                && validation.min_value.is_none_or(|m| v >= i128::from(m))
                && validation.max_value.is_none_or(|m| v <= i128::from(m))
        }
        ScalarValue::Float(f) => {
            let holds = |bound: i64, accept: fn(Ordering) -> bool| {
                compare_float_to_integer(f, bound).is_some_and(accept)
            };
            validation
                .expected_value
                .is_none_or(|e| holds(e, |o| o == Ordering::Equal))
                && validation
                    .min_value
                    .is_none_or(|m| holds(m, |o| o != Ordering::Less))
                && validation
                    .max_value
                    .is_none_or(|m| holds(m, |o| o != Ordering::Greater))
        }
    };
    if !numeric_checks_hold {
        return false;
    }
    if let Some(magic) = &validation.magic_bytes {
        if raw.len() < magic.len() || &raw[..magic.len()] != magic.as_slice() {
            return false;
        }
    }
    true
}

pub(super) fn check_expression_syntax(expression: &str) -> Result<(), TemplateError> {
    if tokenize_expr(expression)?.is_empty() {
        return Err(TemplateError::ExpressionError(
            "expression is empty".to_string(),
        ));
    }
    Ok(())
}

/// Evaluates an `at` or computed-field expression.
///
/// Arithmetic is in `i128`, the type parsed field values are held in, so a
/// `u64` operand at or above 2^63 and a full-width hex literal keep their
/// value. `current_offset` is the value `$` takes: the current offset relative
/// to the enclosing struct's base, the frame `at` positions fields in.
fn evaluate_expression(
    expr: &str,
    values: &ValueScopes,
    current_offset: usize,
    registry: &TemplateRegistry,
) -> Result<i128, TemplateError> {
    let tokens = tokenize_expr(expr)?;
    let mut pos = 0;
    let result = parse_additive(&tokens, &mut pos, values, current_offset, registry, 0)?;
    if pos != tokens.len() {
        return Err(TemplateError::ExpressionError(format!(
            "unexpected trailing tokens in expression: '{expr}'"
        )));
    }
    Ok(result)
}

/// Resolves `sizeof(<type_name>)` to a concrete byte count.
///
/// Tries the built-in primitive table first (matching the names already
/// accepted by template field types), then falls back to the supplied
/// `TemplateRegistry`, summing the size of each field of a registered struct
/// template. A name that matches neither is a [`TemplateError::UnknownType`]
/// rather than a silent zero, so a typo like `sizeof(uint128)` cannot collapse
/// an expression to `0`.
///
/// # Errors
///
/// Returns [`TemplateError::UnknownType`] when `type_name` is neither a known
/// primitive nor a registered fixed-size template.
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
        let size = field_size(&field.field_type).ok_or_else(|| {
            TemplateError::UnknownType(format!(
                "{template_name} (field '{}' has runtime-dependent size)",
                field.name
            ))
        })?;
        total = total
            .checked_add(size)
            .ok_or_else(|| TemplateError::UnknownType(template_name.to_string()))?;
    }
    Ok(total)
}

#[derive(Debug, Clone)]
enum ExprToken {
    Number(i128),
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
                    let val = i128::from_str_radix(&hex_str, 16)
                        .map_err(|e| TemplateError::ExpressionError(format!("bad hex: {e}")))?;
                    tokens.push(ExprToken::Number(val));
                } else {
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    let num_str: String = chars[start..i].iter().collect();
                    let val: i128 = num_str
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
    values: &ValueScopes,
    current_offset: usize,
    registry: &TemplateRegistry,
    depth: usize,
) -> Result<i128, TemplateError> {
    let mut left = parse_multiplicative(tokens, pos, values, current_offset, registry, depth)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            ExprToken::Plus => {
                *pos += 1;
                let right =
                    parse_multiplicative(tokens, pos, values, current_offset, registry, depth)?;
                left = left.wrapping_add(right);
            }
            ExprToken::Minus => {
                *pos += 1;
                let right =
                    parse_multiplicative(tokens, pos, values, current_offset, registry, depth)?;
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
    values: &ValueScopes,
    current_offset: usize,
    registry: &TemplateRegistry,
    depth: usize,
) -> Result<i128, TemplateError> {
    let mut left = parse_unary(tokens, pos, values, current_offset, registry, depth)?;
    while *pos < tokens.len() {
        match &tokens[*pos] {
            ExprToken::Star => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry, depth)?;
                left = left.wrapping_mul(right);
            }
            ExprToken::Slash => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry, depth)?;
                if right == 0 {
                    return Err(TemplateError::ExpressionError(
                        "division by zero".to_string(),
                    ));
                }
                left = left.wrapping_div(right);
            }
            ExprToken::Percent => {
                *pos += 1;
                let right = parse_unary(tokens, pos, values, current_offset, registry, depth)?;
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
    values: &ValueScopes,
    current_offset: usize,
    registry: &TemplateRegistry,
    depth: usize,
) -> Result<i128, TemplateError> {
    if *pos < tokens.len() {
        if let ExprToken::Minus = &tokens[*pos] {
            *pos += 1;
            let val = parse_primary(tokens, pos, values, current_offset, registry, depth)?;
            return Ok(val.wrapping_neg());
        }
    }
    parse_primary(tokens, pos, values, current_offset, registry, depth)
}

fn parse_primary(
    tokens: &[ExprToken],
    pos: &mut usize,
    values: &ValueScopes,
    current_offset: usize,
    registry: &TemplateRegistry,
    depth: usize,
) -> Result<i128, TemplateError> {
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
            i128::try_from(current_offset)
                .map_err(|e| TemplateError::ExpressionError(format!("offset overflow: {e}")))
        }
        ExprToken::Ident(name) => {
            let val = values.get(name).ok_or_else(|| {
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
                            match tokens.get(*pos) {
                                Some(ExprToken::RParen) => *pos += 1,
                                _ => {
                                    return Err(TemplateError::ExpressionError(
                                        "expected closing ')' in sizeof".to_string(),
                                    ));
                                }
                            }
                            let size = resolve_sizeof(&type_name, registry)?;
                            return i128::try_from(size).map_err(|e| {
                                TemplateError::ExpressionError(format!("sizeof overflow: {e}"))
                            });
                        }
                    }
                }
            }
            Err(TemplateError::ExpressionError(
                "invalid sizeof syntax".to_string(),
            ))
        }
        ExprToken::LParen => {
            if depth >= MAX_DEPTH {
                return Err(TemplateError::ExpressionError(format!(
                    "expression nesting exceeds max depth {MAX_DEPTH}"
                )));
            }
            *pos += 1;
            let val = parse_additive(tokens, pos, values, current_offset, registry, depth + 1)?;
            match tokens.get(*pos) {
                Some(ExprToken::RParen) => *pos += 1,
                _ => {
                    return Err(TemplateError::ExpressionError(
                        "expected closing ')'".to_string(),
                    ));
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
                at: None,
                name: "count".to_string(),
                field_type: FieldType::UInt8,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
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
                at: None,
                name: "magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "magic".to_string(),
                    condition_value: 0x5A4D,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        at: None,
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
                at: None,
                name: "magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "magic".to_string(),
                    condition_value: 0xFFFF,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        at: None,
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
                at: None,
                name: "flags".to_string(),
                field_type: FieldType::UInt8,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "flags".to_string(),
                    condition_value,
                    condition_op,
                    fields: vec![FieldDefinition {
                        at: None,
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
            at: None,
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
            at: None,
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
            at: None,
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
        let mut values = ValueScopes::new();
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
                at: None,
                name: "flag".to_string(),
                field_type: FieldType::Bool,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "letter".to_string(),
                field_type: FieldType::Char,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
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

    #[test]
    fn test_sizeof_unknown_type_errors() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let err = evaluate_expression("sizeof(uint128)", &values, 0, &reg)
            .expect_err("sizeof of unknown type must fail");
        match err {
            TemplateError::UnknownType(name) => assert_eq!(name, "uint128"),
            other => panic!("expected UnknownType, got {other:?}"),
        }
    }

    #[test]
    fn test_sizeof_typo_struct_ref_errors() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let err = evaluate_expression("sizeof(SomeStruct)", &values, 0, &reg)
            .expect_err("sizeof of unregistered struct must fail");
        assert!(matches!(err, TemplateError::UnknownType(_)));
    }

    #[test]
    fn test_sizeof_primitives_still_resolve() {
        let reg = make_registry();
        let values = ValueScopes::new();
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

    #[test]
    fn test_sizeof_registered_struct_resolves() {
        let mut reg = make_registry();
        let template = StructTemplate {
            name: "Header".to_string(),
            description: String::new(),
            fields: vec![
                FieldDefinition {
                    at: None,
                    name: "magic".to_string(),
                    field_type: FieldType::UInt32,
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    at: None,
                    name: "version".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    at: None,
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
        let values = ValueScopes::new();
        assert_eq!(
            evaluate_expression("sizeof(Header)", &values, 0, &reg).unwrap(),
            8,
        );
    }

    #[test]
    fn test_eval_pointer_propagates_recursive_error() {
        let mut reg = TemplateRegistry::new();
        let target = StructTemplate {
            name: "Bad".to_string(),
            description: String::new(),
            fields: vec![FieldDefinition {
                at: None,
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
            at: None,
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

    #[test]
    fn test_dynamic_array_pe_import_exact_offsets_and_count() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                at: None,
                name: "import_count".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "import_entries".to_string(),
                field_type: FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt32),
                    count_field: "import_count".to_string(),
                },
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        // import_count (LE u16) = 3, then 3 × LE u32 RVA entries
        let data: [u8; 14] = [
            0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].name, "import_count");
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].size, 2);
        assert_eq!(result[0].raw_bytes, [0x03, 0x00]);
        assert_eq!(result[0].display_value, "3 (0x0003)");

        assert_eq!(result[1].name, "import_entries");
        assert_eq!(result[1].offset, 2);
        assert_eq!(result[1].size, 12);
        assert_eq!(result[1].display_value, "[3 x uint32]");
        assert_eq!(result[1].children.len(), 3);

        assert_eq!(result[1].children[0].name, "[0]");
        assert_eq!(result[1].children[0].offset, 2);
        assert_eq!(result[1].children[0].size, 4);
        assert_eq!(result[1].children[0].raw_bytes, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(result[1].children[0].display_value, "1 (0x00000001)");

        assert_eq!(result[1].children[1].name, "[1]");
        assert_eq!(result[1].children[1].offset, 6);
        assert_eq!(result[1].children[1].size, 4);
        assert_eq!(result[1].children[1].raw_bytes, [0x02, 0x00, 0x00, 0x00]);
        assert_eq!(result[1].children[1].display_value, "2 (0x00000002)");

        assert_eq!(result[1].children[2].name, "[2]");
        assert_eq!(result[1].children[2].offset, 10);
        assert_eq!(result[1].children[2].size, 4);
        assert_eq!(result[1].children[2].raw_bytes, [0x03, 0x00, 0x00, 0x00]);
        assert_eq!(result[1].children[2].display_value, "3 (0x00000003)");
    }

    #[test]
    fn test_conditional_eq_true_emits_exact_field_offset_and_value() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                at: None,
                name: "e_magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "pe_cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "e_magic".to_string(),
                    condition_value: 0x5A4D,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        at: None,
                        name: "e_lfanew".to_string(),
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
        // e_magic = 0x5A4D (MZ LE), e_lfanew = 128 = 0x00000080 (LE)
        let data: [u8; 6] = [0x4D, 0x5A, 0x80, 0x00, 0x00, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[1].name, "e_lfanew");
        assert_eq!(result[1].offset, 2);
        assert_eq!(result[1].size, 4);
        assert_eq!(result[1].raw_bytes, [0x80, 0x00, 0x00, 0x00]);
        assert_eq!(result[1].display_value, "128 (0x00000080)");
    }

    #[test]
    fn test_conditional_eq_false_produces_no_extra_fields() {
        let reg = make_registry();
        let fields = vec![
            FieldDefinition {
                at: None,
                name: "e_magic".to_string(),
                field_type: FieldType::UInt16,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "pe_cond".to_string(),
                field_type: FieldType::Conditional {
                    condition_field: "e_magic".to_string(),
                    condition_value: 0x5A4D,
                    condition_op: ConditionOp::Eq,
                    fields: vec![FieldDefinition {
                        at: None,
                        name: "e_lfanew".to_string(),
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
        // e_magic = 0 (not MZ) — condition is false
        let data: [u8; 6] = [0x00, 0x00, 0x80, 0x00, 0x00, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "e_magic");
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].size, 2);
        assert_eq!(result[0].display_value, "0 (0x0000)");
    }

    #[test]
    fn test_struct_ref_resolves_nested_dos_header_layout_and_values() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "PE_MZ_Fields".to_string(),
            description: String::new(),
            fields: vec![
                FieldDefinition {
                    at: None,
                    name: "e_magic".to_string(),
                    field_type: FieldType::UInt16,
                    endianness: None,
                    description: String::new(),
                    color: None,
                    validation: None,
                },
                FieldDefinition {
                    at: None,
                    name: "e_cblp".to_string(),
                    field_type: FieldType::UInt16,
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
        });

        let fields = vec![
            FieldDefinition {
                at: None,
                name: "prefix".to_string(),
                field_type: FieldType::UInt8,
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
            FieldDefinition {
                at: None,
                name: "dos".to_string(),
                field_type: FieldType::StructRef("PE_MZ_Fields".to_string()),
                endianness: None,
                description: String::new(),
                color: None,
                validation: None,
            },
        ];
        // prefix=0xAA, then PE_MZ_Fields: e_magic=0x5A4D (MZ LE), e_cblp=2 (LE)
        let data: [u8; 5] = [0xAA, 0x4D, 0x5A, 0x02, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].name, "prefix");
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].size, 1);
        assert_eq!(result[0].raw_bytes, [0xAA]);

        assert_eq!(result[1].name, "dos");
        assert_eq!(result[1].offset, 1);
        assert_eq!(result[1].size, 4);
        assert_eq!(result[1].display_value, "struct PE_MZ_Fields");
        assert_eq!(result[1].children.len(), 2);

        assert_eq!(result[1].children[0].name, "e_magic");
        assert_eq!(result[1].children[0].offset, 1);
        assert_eq!(result[1].children[0].size, 2);
        assert_eq!(result[1].children[0].raw_bytes, [0x4D, 0x5A]);
        assert_eq!(result[1].children[0].display_value, "23117 (0x5A4D)");

        assert_eq!(result[1].children[1].name, "e_cblp");
        assert_eq!(result[1].children[1].offset, 3);
        assert_eq!(result[1].children[1].size, 2);
        assert_eq!(result[1].children[1].raw_bytes, [0x02, 0x00]);
        assert_eq!(result[1].children[1].display_value, "2 (0x0002)");
    }

    #[test]
    fn test_pointer_dereferences_to_exact_target_offset_and_value() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "PE_Name_RVA".to_string(),
            description: String::new(),
            fields: vec![FieldDefinition {
                at: None,
                name: "value".to_string(),
                field_type: FieldType::UInt16,
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
        });

        let fields = vec![FieldDefinition {
            at: None,
            name: "name_ptr".to_string(),
            field_type: FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt16),
                target_template: "PE_Name_RVA".to_string(),
            },
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }];

        // ptr value (LE u16 = 4) at [0..2], padding at [2..4], target (0xABCD LE) at [4..6]
        let data: [u8; 6] = [0x04, 0x00, 0x00, 0x00, 0xCD, 0xAB];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "name_ptr");
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].size, 2);
        assert_eq!(result[0].raw_bytes, [0x04, 0x00]);
        assert_eq!(result[0].display_value, "-> 0x4 (PE_Name_RVA)");
        assert_eq!(result[0].children.len(), 1);

        assert_eq!(result[0].children[0].name, "value");
        // Target is at offset 4, not at offset 0 of the pointer field
        assert_eq!(result[0].children[0].offset, 4);
        assert_eq!(result[0].children[0].size, 2);
        assert_eq!(result[0].children[0].raw_bytes, [0xCD, 0xAB]);
        assert_eq!(result[0].children[0].display_value, "43981 (0xABCD)");
    }

    fn fld(name: &str, ft: FieldType) -> FieldDefinition {
        FieldDefinition {
            at: None,
            name: name.to_string(),
            field_type: ft,
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }
    }

    #[test]
    fn test_eval_union_tracks_max_size_and_children() {
        let reg = make_registry();
        let fields = vec![fld(
            "u",
            FieldType::Union {
                variants: vec![
                    fld("as_u8", FieldType::UInt8),
                    fld("as_u32", FieldType::UInt32),
                ],
            },
        )];
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].size, 4, "max variant size (u32) wins");
        assert_eq!(result[0].raw_bytes, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(result[0].display_value, "union<2 variants>");
        assert_eq!(result[0].children.len(), 2);
        assert_eq!(result[0].children[0].name, "as_u8");
        assert_eq!(result[0].children[0].offset, 0);
        assert_eq!(result[0].children[1].name, "as_u32");
        assert_eq!(result[0].children[1].offset, 0);
    }

    #[test]
    fn test_eval_bitfield_flags_set_and_clear() {
        let reg = make_registry();
        let fields = vec![fld(
            "flags",
            FieldType::Bitfield {
                bit_width: 8,
                backing_type: Box::new(FieldType::UInt8),
                flags: Some(vec![
                    ("bit0".to_string(), 0x01),
                    ("bit1".to_string(), 0x02),
                    ("bit2".to_string(), 0x04),
                ]),
            },
        )];
        let data = [0x05u8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].display_value, "0x5 (8:8 bits)");
        assert_eq!(result[0].children.len(), 3);
        assert_eq!(result[0].children[0].display_value, "SET (0x1)");
        assert_eq!(result[0].children[1].display_value, "CLEAR (0x2)");
        assert_eq!(result[0].children[2].display_value, "SET (0x4)");
    }

    #[test]
    fn test_eval_bitfield_width_64_full_mask() {
        let reg = make_registry();
        let fields = vec![fld(
            "wide",
            FieldType::Bitfield {
                bit_width: 64,
                backing_type: Box::new(FieldType::UInt64),
                flags: None,
            },
        )];
        let data = [0xFFu8; 8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].display_value, "0xFFFFFFFFFFFFFFFF (64:64 bits)");
    }

    #[test]
    fn test_eval_bitfield_insufficient_data() {
        let reg = make_registry();
        let fields = vec![fld(
            "wide",
            FieldType::Bitfield {
                bit_width: 8,
                backing_type: Box::new(FieldType::UInt32),
                flags: None,
            },
        )];
        let data = [0x01u8, 0x02];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InsufficientData { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_endianness_switch_big_and_little() {
        let reg = make_registry();
        let big_fields = vec![fld(
            "es",
            FieldType::EndiannessSwitch {
                peek_offset: 0,
                big_value: 0xAB,
            },
        )];
        let data_big = [0xABu8, 0x00];
        let mut eval = TemplateEvaluator::new(&data_big, 0, Endianness::Little, &reg);
        let r = eval.evaluate_fields(&big_fields).unwrap();
        assert!(
            r[0].display_value.starts_with("big"),
            "got {}",
            r[0].display_value
        );

        let data_little = [0x01u8, 0x00];
        let mut eval2 = TemplateEvaluator::new(&data_little, 0, Endianness::Little, &reg);
        let r2 = eval2.evaluate_fields(&big_fields).unwrap();
        assert!(
            r2[0].display_value.starts_with("little"),
            "got {}",
            r2[0].display_value
        );
    }

    #[test]
    fn test_eval_endianness_switch_peek_out_of_bounds() {
        let reg = make_registry();
        let fields = vec![fld(
            "es",
            FieldType::EndiannessSwitch {
                peek_offset: 100,
                big_value: 0xAB,
            },
        )];
        let data = [0x01u8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InsufficientData { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_array_children_fixed_array() {
        let reg = make_registry();
        let fields = vec![fld(
            "arr",
            FieldType::Array {
                element_type: Box::new(FieldType::UInt8),
                count: 3,
            },
        )];
        let data = [0x0Au8, 0x0B, 0x0C];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].size, 3);
        assert_eq!(result[0].children.len(), 3);
        assert_eq!(result[0].children[0].offset, 0);
        assert_eq!(result[0].children[1].offset, 1);
        assert_eq!(result[0].children[2].offset, 2);
        assert_eq!(result[0].children[2].raw_bytes, [0x0C]);
        assert_eq!(result[0].children[0].display_value, "10 (0x0A)");
    }

    #[test]
    fn test_eval_enum_unknown_fallback() {
        let reg = make_registry();
        let fields = vec![fld(
            "e",
            FieldType::Enum {
                backing_type: Box::new(FieldType::UInt8),
                values: vec![("A".to_string(), 1), ("B".to_string(), 2)],
            },
        )];
        let data = [0x63u8]; // 99, not in the value table
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].display_value, "unknown (99, 0x63)");
    }

    #[test]
    fn test_eval_enum_insufficient_data() {
        let reg = make_registry();
        let fields = vec![fld(
            "e",
            FieldType::Enum {
                backing_type: Box::new(FieldType::UInt32),
                values: vec![],
            },
        )];
        let data = [0x01u8, 0x02];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InsufficientData { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_enum_validation_branch() {
        let reg = make_registry();
        let mut f = fld(
            "e",
            FieldType::Enum {
                backing_type: Box::new(FieldType::UInt8),
                values: vec![("A".to_string(), 1)],
            },
        );
        f.validation = Some(FieldValidation {
            expected_value: Some(1),
            min_value: None,
            max_value: None,
            magic_bytes: None,
        });
        let data = [0x01u8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&[f]).unwrap();
        assert_eq!(result[0].validation_passed, Some(true));
    }

    #[test]
    fn test_eval_computed_success_constant_expression() {
        let reg = make_registry();
        let fields = vec![fld(
            "c",
            FieldType::Computed {
                expression: "2 + 3".to_string(),
                display_type: Box::new(FieldType::UInt32),
            },
        )];
        let data = [0u8; 4];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(result[0].size, 0);
        assert_eq!(result[0].display_value, "5 (0x5) = 2 + 3");
    }

    #[test]
    fn test_eval_dynamic_array_missing_count_field() {
        let reg = make_registry();
        let fields = vec![fld(
            "items",
            FieldType::DynamicArray {
                element_type: Box::new(FieldType::UInt8),
                count_field: "absent".to_string(),
            },
        )];
        let data = [0x01u8, 0x02];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidFieldReference(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_dynamic_array_insufficient_data() {
        let reg = make_registry();
        let fields = vec![
            fld("count", FieldType::UInt8),
            fld(
                "items",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt32),
                    count_field: "count".to_string(),
                },
            ),
        ];
        // count = 10 u32 elements = 40 bytes, but only 3 remain
        let data = [0x0Au8, 0x00, 0x00, 0x00];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InsufficientData { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_conditional_missing_condition_field() {
        let reg = make_registry();
        let fields = vec![fld(
            "cond",
            FieldType::Conditional {
                condition_field: "absent".to_string(),
                condition_value: 0,
                condition_op: ConditionOp::Eq,
                fields: vec![],
            },
        )];
        let data = [0x00u8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidFieldReference(_)),
            "got {err:?}"
        );
    }

    fn conditional_emits_inner(op: ConditionOp, cond_value: i64, flag_byte: u8) -> usize {
        let reg = make_registry();
        let fields = make_bitmask_fields(op, cond_value);
        let data = [flag_byte, 0xAA];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        eval.evaluate_fields(&fields).unwrap().len()
    }

    #[test]
    fn test_eval_conditional_relational_ops() {
        // Ne: 0x10 != 0xFF -> emits inner (len 2)
        assert_eq!(conditional_emits_inner(ConditionOp::Ne, 0xFF, 0x10), 2);
        // Gt: 0x10 > 0x05 -> emits
        assert_eq!(conditional_emits_inner(ConditionOp::Gt, 0x05, 0x10), 2);
        // Lt: 0x05 < 0x10 -> emits
        assert_eq!(conditional_emits_inner(ConditionOp::Lt, 0x10, 0x05), 2);
        // Ge: 0x10 >= 0x10 -> emits
        assert_eq!(conditional_emits_inner(ConditionOp::Ge, 0x10, 0x10), 2);
        // Le: 0x05 <= 0x10 -> emits
        assert_eq!(conditional_emits_inner(ConditionOp::Le, 0x10, 0x05), 2);
        // And their false arms:
        assert_eq!(conditional_emits_inner(ConditionOp::Ne, 0x10, 0x10), 1);
        assert_eq!(conditional_emits_inner(ConditionOp::Gt, 0x10, 0x05), 1);
        assert_eq!(conditional_emits_inner(ConditionOp::Lt, 0x05, 0x10), 1);
        assert_eq!(conditional_emits_inner(ConditionOp::Ge, 0x10, 0x05), 1);
        assert_eq!(conditional_emits_inner(ConditionOp::Le, 0x05, 0x10), 1);
    }

    #[test]
    fn test_eval_struct_ref_not_found() {
        let reg = make_registry();
        let fields = vec![fld("s", FieldType::StructRef("NoSuchStruct".to_string()))];
        let data = [0u8; 8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(&err, TemplateError::NotFound(n) if n == "NoSuchStruct"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_struct_ref_circular_reference() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "Rec".to_string(),
            description: String::new(),
            fields: vec![fld("self_ref", FieldType::StructRef("Rec".to_string()))],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        let fields = vec![fld("root", FieldType::StructRef("Rec".to_string()))];
        let data = [0u8; 8];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::CircularReference(_)),
            "got {err:?}"
        );
    }

    /// A pointer whose target template name is not registered must error with
    /// `NotFound`, like `StructRef`, instead of silently yielding a pointer
    /// with no children, which would hide a typo in the template name.
    #[test]
    fn test_pointer_to_unregistered_template_is_not_found() {
        let reg = TemplateRegistry::new();
        let fields = vec![FieldDefinition {
            at: None,
            name: "bad_ptr".to_string(),
            field_type: FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt16),
                target_template: "Nonexistent".to_string(),
            },
            endianness: None,
            description: String::new(),
            color: None,
            validation: None,
        }];
        // The LE u16 pointer value is 4, an in-range address into the buffer,
        // so evaluation reaches the (unregistered) target lookup.
        let data: [u8; 6] = [0x04, 0x00, 0x00, 0x00, 0xCD, 0xAB];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::NotFound(ref n) if n == "Nonexistent"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_pointer_insufficient_data() {
        let reg = make_registry();
        let fields = vec![fld(
            "p",
            FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt32),
                target_template: "whatever".to_string(),
            },
        )];
        let data = [0x01u8, 0x02];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).unwrap_err();
        assert!(
            matches!(err, TemplateError::InsufficientData { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_check_validation_min_max_magic() {
        // min_value
        let min_v = FieldValidation {
            expected_value: None,
            min_value: Some(10),
            max_value: None,
            magic_bytes: None,
        };
        assert!(!check_validation(&min_v, ScalarValue::Integer(5), &[]));
        assert!(check_validation(&min_v, ScalarValue::Integer(15), &[]));
        // max_value
        let max_v = FieldValidation {
            expected_value: None,
            min_value: None,
            max_value: Some(5),
            magic_bytes: None,
        };
        assert!(!check_validation(&max_v, ScalarValue::Integer(10), &[]));
        assert!(check_validation(&max_v, ScalarValue::Integer(3), &[]));
        // magic_bytes: match, mismatch, and short-raw
        let magic = FieldValidation {
            expected_value: None,
            min_value: None,
            max_value: None,
            magic_bytes: Some(vec![0xAA, 0xBB]),
        };
        assert!(check_validation(
            &magic,
            ScalarValue::Integer(0),
            &[0xAA, 0xBB, 0xCC]
        ));
        assert!(!check_validation(
            &magic,
            ScalarValue::Integer(0),
            &[0xAA, 0xFF]
        ));
        let long_magic = FieldValidation {
            expected_value: None,
            min_value: None,
            max_value: None,
            magic_bytes: Some(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        };
        assert!(!check_validation(
            &long_magic,
            ScalarValue::Integer(0),
            &[0xAA, 0xBB]
        ));
    }

    #[test]
    fn test_expression_div_mod_and_zero_errors() {
        let reg = make_registry();
        let values = ValueScopes::new();
        assert_eq!(evaluate_expression("20 / 4", &values, 0, &reg).unwrap(), 5);
        assert_eq!(evaluate_expression("20 % 6", &values, 0, &reg).unwrap(), 2);
        let div0 = evaluate_expression("5 / 0", &values, 0, &reg).unwrap_err();
        assert!(
            matches!(&div0, TemplateError::ExpressionError(m) if m.contains("division by zero"))
        );
        let mod0 = evaluate_expression("5 % 0", &values, 0, &reg).unwrap_err();
        assert!(matches!(&mod0, TemplateError::ExpressionError(m) if m.contains("modulo by zero")));
    }

    #[test]
    fn test_expression_unary_minus_and_hex() {
        let reg = make_registry();
        let values = ValueScopes::new();
        assert_eq!(evaluate_expression("-5", &values, 0, &reg).unwrap(), -5);
        assert_eq!(evaluate_expression("-5 + 3", &values, 0, &reg).unwrap(), -2);
        assert_eq!(evaluate_expression("0x10", &values, 0, &reg).unwrap(), 16);
        assert_eq!(
            evaluate_expression("0xFF + 1", &values, 0, &reg).unwrap(),
            256
        );
    }

    #[test]
    fn test_expression_error_paths() {
        let reg = make_registry();
        let values = ValueScopes::new();
        // bad hex literal
        assert!(matches!(
            evaluate_expression("0x", &values, 0, &reg).unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("bad hex")
        ));
        // bad (overflowing) decimal literal: past i128::MAX
        assert!(matches!(
            evaluate_expression("9999999999999999999999999999999999999999", &values, 0, &reg)
                .unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("bad number")
        ));
        // unexpected character
        assert!(matches!(
            evaluate_expression("3 @ 4", &values, 0, &reg).unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("unexpected character")
        ));
        // unexpected token at primary position
        assert!(matches!(
            evaluate_expression(")", &values, 0, &reg).unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("unexpected token")
        ));
        // unexpected end of expression
        assert!(matches!(
            evaluate_expression("5 +", &values, 0, &reg).unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("unexpected end")
        ));
        // invalid sizeof syntax (no parenthesized type)
        assert!(matches!(
            evaluate_expression("sizeof 5", &values, 0, &reg).unwrap_err(),
            TemplateError::ExpressionError(m) if m.contains("invalid sizeof syntax")
        ));
    }

    /// `$` carries the whole `usize` offset range; nothing is lost or rejected
    /// at the top of it.
    #[test]
    fn test_expression_dollar_keeps_the_full_offset_range() {
        let reg = make_registry();
        let values = ValueScopes::new();
        assert_eq!(
            evaluate_expression("$", &values, usize::MAX, &reg).unwrap(),
            i128::from(u64::MAX)
        );
    }

    /// `at` positions a field relative to the enclosing struct's base, and `$`
    /// is the current offset in that same frame, for `at` and computed fields
    /// alike. Taking the absolute offset instead adds the base twice: in a
    /// struct starting at 1, `$ + 1` after one field lands at 4 instead of 3.
    #[test]
    fn test_dollar_is_relative_to_the_enclosing_struct() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl(
            "Inner",
            vec![
                fld("x", FieldType::UInt8),
                positioned("$ + 1", fld("y", FieldType::UInt8)),
                fld(
                    "pos",
                    FieldType::Computed {
                        expression: "$".to_string(),
                        display_type: Box::new(FieldType::UInt32),
                    },
                ),
            ],
        ));
        let outer = vec![
            fld("a", FieldType::UInt8),
            fld("inner", FieldType::StructRef("Inner".to_string())),
        ];
        let result = apply_fields(&reg, &outer, &[0x10, 0x20, 0x30, 0x40, 0x50]).unwrap();
        let inner = &result[1].children;
        assert_eq!(inner[1].name, "y");
        assert_eq!(inner[1].offset, 3);
        assert_eq!(inner[1].raw_bytes, [0x40]);
        assert_eq!(inner[2].display_value, "3 (0x3) = $");
    }

    /// Expression operands keep a field's full value: truncating to `i64`
    /// turns a `u64` at or above 2^63 negative, and a full-width hex literal
    /// must parse rather than fail as too large.
    #[test]
    fn test_expressions_keep_full_u64_operands() {
        let reg = make_registry();
        let computed = |expression: &str| FieldType::Computed {
            expression: expression.to_string(),
            display_type: Box::new(FieldType::UInt64),
        };
        let fields = vec![
            fld("big", FieldType::UInt64),
            fld("echo", computed("big")),
            fld("rest", computed("0xFFFFFFFFFFFFFFFF - big")),
        ];
        let data = 0x8000_0000_0000_0000u64.to_le_bytes();
        let result = apply_fields(&reg, &fields, &data).unwrap();
        assert_eq!(
            result[1].display_value,
            "9223372036854775808 (0x8000000000000000) = big"
        );
        assert_eq!(
            result[2].display_value,
            "9223372036854775807 (0x7FFFFFFFFFFFFFFF) = 0xFFFFFFFFFFFFFFFF - big"
        );
    }

    #[test]
    fn test_sizeof_runtime_dependent_field_errors() {
        let mut reg = make_registry();
        reg.register(StructTemplate {
            name: "HasDyn".to_string(),
            description: String::new(),
            fields: vec![fld(
                "items",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "n".to_string(),
                },
            )],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        let values = ValueScopes::new();
        let err = evaluate_expression("sizeof(HasDyn)", &values, 0, &reg).unwrap_err();
        assert!(
            matches!(&err, TemplateError::UnknownType(m) if m.contains("runtime-dependent")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_sizeof_zero_padding_field_resolves() {
        let mut reg = make_registry();
        reg.register(StructTemplate {
            name: "WithZeroPad".to_string(),
            description: String::new(),
            fields: vec![
                fld("pad", FieldType::Padding(0)),
                fld("v", FieldType::UInt32),
            ],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        let values = ValueScopes::new();
        // Padding(0) is a legitimate zero-size type -> total = 0 + 4 = 4.
        assert_eq!(
            evaluate_expression("sizeof(WithZeroPad)", &values, 0, &reg).unwrap(),
            4
        );
    }

    #[test]
    fn test_sizeof_struct_size_overflow_errors() {
        let mut reg = make_registry();
        reg.register(StructTemplate {
            name: "Huge".to_string(),
            description: String::new(),
            fields: vec![
                fld("a", FieldType::Bytes(usize::MAX)),
                fld("b", FieldType::Bytes(usize::MAX)),
            ],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        let values = ValueScopes::new();
        let err = evaluate_expression("sizeof(Huge)", &values, 0, &reg).unwrap_err();
        assert!(
            matches!(&err, TemplateError::UnknownType(n) if n == "Huge"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_expression_nested_parens_within_limit_succeeds() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let nested = format!("{}42{}", "(".repeat(10), ")".repeat(10));
        assert_eq!(evaluate_expression(&nested, &values, 0, &reg).unwrap(), 42);
    }

    #[test]
    fn test_expression_deep_nested_parens_rejected_not_unbounded() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let nested = format!("{}1{}", "(".repeat(500), ")".repeat(500));
        let err = evaluate_expression(&nested, &values, 0, &reg).expect_err(
            "expression nesting far beyond MAX_DEPTH must be rejected by a depth guard",
        );
        assert!(
            matches!(&err, TemplateError::ExpressionError(m) if m.contains("depth")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_expression_trailing_tokens_rejected() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let err = evaluate_expression("5 + 3 3", &values, 0, &reg)
            .expect_err("trailing tokens after a complete expression must error");
        assert!(
            matches!(&err, TemplateError::ExpressionError(m) if m.contains("trailing")),
            "got {err:?}"
        );

        let err2 = evaluate_expression("sizeof(u8) extra_garbage", &values, 0, &reg)
            .expect_err("trailing garbage after sizeof(...) must error");
        assert!(
            matches!(err2, TemplateError::ExpressionError(_)),
            "got {err2:?}"
        );

        let err3 = evaluate_expression("$ + 4 )", &values, 0x10, &reg)
            .expect_err("a stray trailing ')' must error, not be silently ignored");
        assert!(
            matches!(err3, TemplateError::ExpressionError(_)),
            "got {err3:?}"
        );
    }

    #[test]
    fn test_expression_unbalanced_open_paren_rejected() {
        let reg = make_registry();
        let values = ValueScopes::new();
        let err = evaluate_expression("(5 + 3", &values, 0, &reg)
            .expect_err("missing closing ')' must error");
        assert!(
            matches!(&err, TemplateError::ExpressionError(m) if m.contains("closing")),
            "got {err:?}"
        );
    }

    /// Negating the most negative `i64` is exact in the `i128` arithmetic, and
    /// negating the most negative `i128` wraps rather than panicking.
    #[test]
    fn test_expression_unary_neg_is_exact_and_never_panics() {
        let reg = make_registry();
        let mut values = ValueScopes::new();
        values.insert("m".to_string(), i128::from(i64::MIN));
        values.insert("w".to_string(), i128::MIN);
        assert_eq!(
            evaluate_expression("-m", &values, 0, &reg).unwrap(),
            -i128::from(i64::MIN)
        );
        assert_eq!(
            evaluate_expression("-w", &values, 0, &reg).unwrap(),
            i128::MIN
        );
    }

    #[test]
    fn test_array_of_unsized_element_rejected_not_offset_corrupting() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "Elem".to_string(),
            description: String::new(),
            fields: vec![fld("v", FieldType::UInt8)],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        let fields = vec![
            fld(
                "sections",
                FieldType::Array {
                    element_type: Box::new(FieldType::StructRef("Elem".to_string())),
                    count: 3,
                },
            ),
            fld("after", FieldType::UInt8),
        ];
        let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval
            .evaluate_fields(&fields)
            .expect_err("Array of an unsized element type must error, not silently size to 0");
        assert!(
            matches!(err, TemplateError::UnsizedFieldType(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_dynamic_array_composite_element_type_rejected() {
        let reg = make_registry();
        let fields = vec![
            fld("count", FieldType::UInt32),
            fld(
                "items",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::Union { variants: vec![] }),
                    count_field: "count".to_string(),
                },
            ),
        ];
        let mut data = vec![0u8; 4];
        data[..4].copy_from_slice(&1000u32.to_le_bytes());
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&fields).expect_err(
            "DynamicArray with a zero-sized composite element_type must error, not build \
             `count` empty ParsedField entries unbounded by data length",
        );
        assert!(
            matches!(err, TemplateError::UnsizedFieldType(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn test_eval_array_children_zero_size_element_no_unbounded_loop() {
        let reg = make_registry();
        let fields = vec![fld(
            "arr",
            FieldType::Array {
                element_type: Box::new(FieldType::Padding(0)),
                count: 10_000,
            },
        )];
        let data = [0u8; 4];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(
            result[0].children.len(),
            0,
            "zero-sized array elements must not be expanded into per-element children"
        );
    }

    #[test]
    fn test_dynamic_array_count_field_reads_float32_value_correctly() {
        let reg = make_registry();
        let fields = vec![
            fld("count_f", FieldType::Float32),
            fld(
                "items",
                FieldType::DynamicArray {
                    element_type: Box::new(FieldType::UInt8),
                    count_field: "count_f".to_string(),
                },
            ),
        ];
        let mut data = 2.0f32.to_le_bytes().to_vec();
        data.extend_from_slice(&[0xAA, 0xBB]);
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let result = eval.evaluate_fields(&fields).unwrap();
        assert_eq!(
            result[1].children.len(),
            2,
            "Float32 count_field must be read as its real truncated value (2), not silently 0"
        );
    }

    #[test]
    fn test_eval_pointer_depth_exceeded_errors_like_struct_ref() {
        let mut reg = TemplateRegistry::new();
        reg.register(StructTemplate {
            name: "SelfPtr".to_string(),
            description: String::new(),
            fields: vec![fld(
                "next",
                FieldType::Pointer {
                    pointer_type: Box::new(FieldType::UInt32),
                    target_template: "SelfPtr".to_string(),
                },
            )],
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        });
        // Pointer value 0 always dereferences back to the start of this same
        // 4-byte buffer, forming an unbounded cycle without the depth guard.
        let data = [0u8; 4];
        let outer = vec![fld(
            "root",
            FieldType::Pointer {
                pointer_type: Box::new(FieldType::UInt32),
                target_template: "SelfPtr".to_string(),
            },
        )];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval.evaluate_fields(&outer).expect_err(
            "a cyclic pointer chain must error at MAX_DEPTH instead of silently truncating",
        );
        assert!(
            matches!(err, TemplateError::CircularReference(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn test_sized_field_offset_overflow_is_insufficient_data_not_panic() {
        let reg = TemplateRegistry::new();
        // A one-byte field advances current_offset to 1, then a byte field
        // whose declared size is usize::MAX makes `1 + usize::MAX` overflow.
        let fields = vec![
            fld("head", FieldType::UInt8),
            fld("huge", FieldType::Bytes(usize::MAX)),
        ];
        let data = [0u8; 4];
        let mut eval = TemplateEvaluator::new(&data, 0, Endianness::Little, &reg);
        let err = eval
            .evaluate_fields(&fields)
            .expect_err("an overflowing field size must error, never panic");
        assert!(
            matches!(
                err,
                TemplateError::InsufficientData {
                    offset: 1,
                    needed: usize::MAX,
                    available: 3
                }
            ),
            "expected InsufficientData{{offset:1, needed:usize::MAX, available:3}}, got {err:?}"
        );
    }

    fn tmpl(name: &str, fields: Vec<FieldDefinition>) -> StructTemplate {
        StructTemplate {
            name: name.to_string(),
            description: String::new(),
            fields,
            default_endianness: Endianness::Little,
            version: None,
            author: None,
            category: None,
            magic_detection: None,
        }
    }

    fn bounds(expected: Option<i64>, min: Option<i64>, max: Option<i64>) -> FieldValidation {
        FieldValidation {
            expected_value: expected,
            min_value: min,
            max_value: max,
            magic_bytes: None,
        }
    }

    fn validated(name: &str, ft: FieldType, validation: FieldValidation) -> FieldDefinition {
        FieldDefinition {
            validation: Some(validation),
            ..fld(name, ft)
        }
    }

    fn positioned(expression: &str, field: FieldDefinition) -> FieldDefinition {
        FieldDefinition {
            at: Some(expression.to_string()),
            ..field
        }
    }

    fn pointer_to(target: &str, pointer_type: FieldType) -> FieldType {
        FieldType::Pointer {
            pointer_type: Box::new(pointer_type),
            target_template: target.to_string(),
        }
    }

    fn dynamic_array(count_field: &str) -> FieldType {
        FieldType::DynamicArray {
            element_type: Box::new(FieldType::UInt8),
            count_field: count_field.to_string(),
        }
    }

    fn cond(field: &str, op: ConditionOp, value: i64, inner: &str) -> FieldDefinition {
        fld(
            &format!("if_{inner}"),
            FieldType::Conditional {
                condition_field: field.to_string(),
                condition_value: value,
                condition_op: op,
                fields: vec![fld(inner, FieldType::UInt8)],
            },
        )
    }

    fn apply_fields(
        reg: &TemplateRegistry,
        fields: &[FieldDefinition],
        data: &[u8],
    ) -> Result<Vec<ParsedField>, TemplateError> {
        TemplateEvaluator::new(data, 0, Endianness::Little, reg).evaluate_fields(fields)
    }

    fn validate_scalar(ft: FieldType, raw: &[u8], validation: FieldValidation) -> Option<bool> {
        let reg = make_registry();
        let result = apply_fields(&reg, &[validated("v", ft, validation)], raw).unwrap();
        result[0].validation_passed
    }

    fn fan_out_registry(levels: usize, link: fn(&str) -> FieldType) -> TemplateRegistry {
        let mut reg = TemplateRegistry::new();
        for level in 0..levels {
            let next = format!("FanOut{}", level + 1);
            let fields = (0..4).map(|i| fld(&format!("r{i}"), link(&next))).collect();
            reg.register(tmpl(&format!("FanOut{level}"), fields));
        }
        reg.register(tmpl(
            &format!("FanOut{levels}"),
            vec![fld("leaf", FieldType::Padding(0))],
        ));
        reg
    }

    #[test]
    fn test_struct_ref_fan_out_hits_work_budget() {
        let link: fn(&str) -> FieldType = |next| FieldType::StructRef(next.to_string());

        let small = fan_out_registry(6, link);
        let fields = small.apply("FanOut0", &[0u8; 4], 0).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].display_value, "struct FanOut1");

        let huge = fan_out_registry(10, link);
        let err = huge
            .apply("FanOut0", &[0u8; 4], 0)
            .expect_err("a 4^10 fan-out must exceed the work budget");
        assert!(
            matches!(&err, TemplateError::ResourceLimit(m) if m.contains("1048576")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_pointer_fan_out_hits_work_budget() {
        let link: fn(&str) -> FieldType = |next| pointer_to(next, FieldType::UInt8);

        let huge = fan_out_registry(10, link);
        let err = huge
            .apply("FanOut0", &[0u8; 4], 0)
            .expect_err("a 4^10 pointer fan-out must exceed the work budget");
        assert!(
            matches!(&err, TemplateError::ResourceLimit(m) if m.contains("1048576")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_pointer_fan_out_of_large_bytes_hits_output_budget() {
        // Pointing many times at one large Bytes region copies that region once
        // per pointer, so a few hundred fields can amplify a 20 KiB file into
        // megabytes of parsed output. The field-count budget never bites here
        // (300 fields), so the output byte budget is the only bound.
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("Blob", vec![fld("payload", FieldType::Bytes(20_000))]));
        let pointers: Vec<FieldDefinition> = (0..150)
            .map(|i| fld(&format!("p{i}"), pointer_to("Blob", FieldType::UInt16)))
            .collect();
        reg.register(tmpl("Root", pointers));

        let data = vec![0u8; 20_000];
        let err = reg
            .apply("Root", &data, 0)
            .expect_err("150 pointers each copying a 20 KiB blob must exceed the output budget");
        let expected_budget = 20_000usize * OUTPUT_BYTES_PER_INPUT_BYTE + OUTPUT_BYTE_FLOOR;
        assert!(
            matches!(&err, TemplateError::ResourceLimit(m)
                if m.contains("copied bytes") && m.contains(&expected_budget.to_string())),
            "got {err:?}"
        );
    }

    #[test]
    fn test_u64_pointer_above_i64_max_is_not_dereferenced() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("Target", vec![fld("marker", FieldType::UInt8)]));
        let fields = vec![fld("ptr", pointer_to("Target", FieldType::UInt64))];

        let mut data = vec![0xEE; 16];
        data[..8].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
        let result = apply_fields(&reg, &fields, &data).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].display_value, "-> 0x8000000000000000 (Target)");
        assert_eq!(result[0].children.len(), 0);
        assert_eq!(result[0].size, 8);
    }

    #[test]
    fn test_dynamic_array_count_above_i64_max_is_insufficient_data() {
        let reg = make_registry();
        let fields = vec![
            fld("n", FieldType::UInt64),
            fld("items", dynamic_array("n")),
        ];
        let mut data = 0x8000_0000_0000_0000u64.to_le_bytes().to_vec();
        data.extend_from_slice(&[1, 2, 3, 4]);

        let err = apply_fields(&reg, &fields, &data).expect_err("a 2^63 element count cannot fit");
        assert!(
            matches!(
                err,
                TemplateError::InsufficientData {
                    offset: 8,
                    needed: 0x8000_0000_0000_0000,
                    available: 4
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_u64_validation_uses_exact_value() {
        let all_ones = [0xFF; 8];
        assert_eq!(
            validate_scalar(FieldType::UInt64, &all_ones, bounds(None, Some(0), None)),
            Some(true)
        );
        assert_eq!(
            validate_scalar(FieldType::UInt64, &all_ones, bounds(Some(-1), None, None)),
            Some(false)
        );
        assert_eq!(
            validate_scalar(
                FieldType::UInt64,
                &all_ones,
                bounds(None, None, Some(i64::MAX))
            ),
            Some(false)
        );
        assert_eq!(
            validate_scalar(FieldType::Int64, &all_ones, bounds(Some(-1), None, None)),
            Some(true)
        );
    }

    #[test]
    fn test_conditions_compare_exact_u64_values() {
        let reg = make_registry();
        let fields = vec![
            fld("big", FieldType::UInt64),
            cond("big", ConditionOp::Gt, 0, "gt"),
            cond("big", ConditionOp::Lt, 0, "lt"),
            cond("big", ConditionOp::Ge, i64::MAX, "ge_max"),
            cond("big", ConditionOp::Eq, i64::MIN, "eq_min"),
            cond("big", ConditionOp::BitAnd, i64::MIN, "bit63"),
        ];
        let mut data = 0x8000_0000_0000_0000u64.to_le_bytes().to_vec();
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let result = apply_fields(&reg, &fields, &data).unwrap();
        let names: Vec<&str> = result.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["big", "gt", "ge_max", "bit63"]);
        assert_eq!(result[1].offset, 8);
        assert_eq!(result[2].offset, 9);
        assert_eq!(result[3].offset, 10);
    }

    #[test]
    fn test_struct_ref_scopes_parsed_values() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("InnerCount", vec![fld("count", FieldType::UInt8)]));
        reg.register(tmpl("InnerHidden", vec![fld("hidden", FieldType::UInt8)]));
        reg.register(tmpl("InnerBody", vec![fld("body", dynamic_array("len"))]));

        let shadow = vec![
            fld("count", FieldType::UInt8),
            fld("inner", FieldType::StructRef("InnerCount".to_string())),
            fld("items", dynamic_array("count")),
        ];
        let result = apply_fields(&reg, &shadow, &[2, 5, 0xAA, 0xBB]).unwrap();
        assert_eq!(result[2].name, "items");
        assert_eq!(result[2].offset, 2);
        assert_eq!(result[2].size, 2);
        assert_eq!(result[2].raw_bytes, [0xAA, 0xBB]);
        assert_eq!(result[2].children.len(), 2);

        let leak = vec![
            fld("inner", FieldType::StructRef("InnerHidden".to_string())),
            fld("items", dynamic_array("hidden")),
        ];
        let err = apply_fields(&reg, &leak, &[1, 0xAA]).unwrap_err();
        assert!(
            matches!(&err, TemplateError::InvalidFieldReference(m) if m.contains("hidden")),
            "got {err:?}"
        );

        let outer_visible = vec![
            fld("len", FieldType::UInt8),
            fld("hdr", FieldType::StructRef("InnerBody".to_string())),
        ];
        let result = apply_fields(&reg, &outer_visible, &[3, 1, 2, 3]).unwrap();
        assert_eq!(result[1].children.len(), 1);
        assert_eq!(result[1].children[0].name, "body");
        assert_eq!(result[1].children[0].children.len(), 3);
    }

    #[test]
    fn test_pointer_target_does_not_clobber_outer_value() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("Tgt", vec![fld("count", FieldType::UInt8)]));
        let fields = vec![
            fld("count", FieldType::UInt8),
            fld("p", pointer_to("Tgt", FieldType::UInt8)),
            fld("items", dynamic_array("count")),
        ];
        let data = [1u8, 4, 0xCC, 0x00, 7];
        let result = apply_fields(&reg, &fields, &data).unwrap();

        assert_eq!(result[1].children.len(), 1);
        assert_eq!(result[1].children[0].offset, 4);
        assert_eq!(result[1].children[0].display_value, "7 (0x07)");
        assert_eq!(result[2].offset, 2);
        assert_eq!(result[2].size, 1);
        assert_eq!(result[2].raw_bytes, [0xCC]);
    }

    #[test]
    fn test_float_validation_uses_real_value_and_rejects_nan() {
        let single = |v: f32| (FieldType::Float32, v.to_le_bytes().to_vec());
        let double = |v: f64| (FieldType::Float64, v.to_le_bytes().to_vec());
        let magic_only = FieldValidation {
            magic_bytes: Some(vec![0x00, 0x00]),
            ..bounds(None, None, None)
        };

        let cases = [
            (single(3.9), bounds(None, None, Some(3)), Some(false)),
            (single(3.0), bounds(None, None, Some(3)), Some(true)),
            (single(3.9), bounds(None, Some(3), None), Some(true)),
            (single(3.9), bounds(Some(3), None, None), Some(false)),
            (double(2.5), bounds(Some(2), None, None), Some(false)),
            (double(2.0), bounds(Some(2), None, None), Some(true)),
            (double(-3.9), bounds(None, Some(-3), None), Some(false)),
            (double(-0.5), bounds(Some(0), None, None), Some(false)),
            (
                double(9.3e18),
                bounds(None, None, Some(i64::MAX)),
                Some(false),
            ),
            (
                double(9.3e18),
                bounds(None, Some(i64::MAX), None),
                Some(true),
            ),
            (
                double(-9.3e18),
                bounds(None, Some(i64::MIN), None),
                Some(false),
            ),
            (
                double(f64::INFINITY),
                bounds(None, None, Some(i64::MAX)),
                Some(false),
            ),
            (single(f32::NAN), bounds(Some(0), None, None), Some(false)),
            (single(f32::NAN), bounds(None, Some(-5), None), Some(false)),
            (single(f32::NAN), bounds(None, None, Some(5)), Some(false)),
            (single(f32::NAN), magic_only, Some(true)),
        ];
        for ((ft, raw), validation, expected) in cases {
            let described = format!("{ft:?} {raw:02X?} {validation:?}");
            assert_eq!(
                validate_scalar(ft, &raw, validation),
                expected,
                "{described}"
            );
        }
    }

    #[test]
    fn test_bool_numeric_value_is_zero_or_one() {
        let reg = make_registry();
        let fields = vec![
            validated("flag", FieldType::Bool, bounds(Some(1), None, None)),
            cond("flag", ConditionOp::Eq, 1, "when_true"),
        ];
        let result = apply_fields(&reg, &fields, &[0x02, 0x7F]).unwrap();

        assert_eq!(result[0].display_value, "true");
        assert_eq!(result[0].validation_passed, Some(true));
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].name, "when_true");
        assert_eq!(result[1].offset, 1);
    }

    #[test]
    fn test_pointer_with_enum_pointer_type_dereferences() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("Target", vec![fld("value", FieldType::UInt16)]));
        let enum_ptr = pointer_to(
            "Target",
            FieldType::Enum {
                backing_type: Box::new(FieldType::UInt16),
                values: Vec::new(),
            },
        );
        let data = [0x04, 0x00, 0x00, 0x00, 0xCD, 0xAB];
        let result = apply_fields(&reg, &[fld("p", enum_ptr)], &data).unwrap();

        assert_eq!(result[0].display_value, "-> 0x4 (Target)");
        assert_eq!(result[0].children.len(), 1);
        assert_eq!(result[0].children[0].offset, 4);
        assert_eq!(result[0].children[0].display_value, "43981 (0xABCD)");
    }

    #[test]
    fn test_fixed_array_children_are_capped() {
        let reg = make_registry();
        let array = |count: usize| {
            fld(
                "arr",
                FieldType::Array {
                    element_type: Box::new(FieldType::UInt8),
                    count,
                },
            )
        };
        let data: Vec<u8> = (0..70_001u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();

        let fields = vec![array(70_000), fld("tail", FieldType::UInt8)];
        let result = apply_fields(&reg, &fields, &data).unwrap();
        assert_eq!(result[0].size, 70_000);
        assert_eq!(result[0].raw_bytes.len(), 70_000);
        assert_eq!(
            result[0].display_value,
            "[70000 x uint8] (first 65536 elements shown)"
        );
        assert_eq!(result[0].children.len(), 65_536);
        assert_eq!(result[0].children[65_535].name, "[65535]");
        assert_eq!(result[0].children[65_535].offset, 65_535);
        assert_eq!(result[1].offset, 70_000);

        let at_cap = apply_fields(&reg, &[array(65_536)], &data).unwrap();
        assert_eq!(at_cap[0].display_value, "[65536 x uint8]");
        assert_eq!(at_cap[0].children.len(), 65_536);
    }

    #[test]
    fn test_dynamic_array_children_are_capped() {
        let reg = make_registry();
        let fields = vec![
            fld("n", FieldType::UInt32),
            fld("items", dynamic_array("n")),
            fld("tail", FieldType::UInt8),
        ];
        let mut data = 70_000u32.to_le_bytes().to_vec();
        data.extend(std::iter::repeat_n(0x5Au8, 70_000));
        data.push(0xEE);

        let result = apply_fields(&reg, &fields, &data).unwrap();
        assert_eq!(result[1].size, 70_000);
        assert_eq!(result[1].raw_bytes.len(), 70_000);
        assert_eq!(
            result[1].display_value,
            "[70000 x uint8] (first 65536 elements shown)"
        );
        assert_eq!(result[1].children.len(), 65_536);
        assert_eq!(result[1].children[65_535].offset, 4 + 65_535);
        assert_eq!(result[2].offset, 70_004);
        assert_eq!(result[2].display_value, "238 (0xEE)");
    }

    #[test]
    fn test_at_positions_a_field_without_moving_the_cursor_backward() {
        let reg = make_registry();

        let forward = vec![
            fld("off", FieldType::UInt8),
            positioned("off", fld("late", FieldType::UInt8)),
            fld("next", FieldType::UInt8),
        ];
        let data = [4u8, 0xA1, 0xA2, 0xA3, 0xB0, 0xC0];
        let result = apply_fields(&reg, &forward, &data).unwrap();
        assert_eq!(result[1].name, "late");
        assert_eq!(result[1].offset, 4);
        assert_eq!(result[1].display_value, "176 (0xB0)");
        assert_eq!(result[2].name, "next");
        assert_eq!(result[2].offset, 5);
        assert_eq!(result[2].display_value, "192 (0xC0)");

        let backward = vec![
            fld("a", FieldType::UInt16),
            fld("b", FieldType::UInt16),
            positioned("0", fld("back", FieldType::UInt8)),
            fld("c", FieldType::UInt8),
        ];
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let result = apply_fields(&reg, &backward, &data).unwrap();
        assert_eq!(result[2].name, "back");
        assert_eq!(result[2].offset, 0);
        assert_eq!(result[2].display_value, "17 (0x11)");
        assert_eq!(result[3].name, "c");
        assert_eq!(result[3].offset, 4);
        assert_eq!(result[3].display_value, "85 (0x55)");

        let relative = vec![positioned("1", fld("x", FieldType::UInt8))];
        let data = [0u8, 0, 0xAA, 0xBB, 0xCC];
        let result = TemplateEvaluator::new(&data, 2, Endianness::Little, &reg)
            .evaluate_fields(&relative)
            .unwrap();
        assert_eq!(result[0].offset, 3);
        assert_eq!(result[0].display_value, "187 (0xBB)");

        let maybe = |flag: u8| {
            let fields = vec![
                fld("flag", FieldType::UInt8),
                positioned(
                    "5",
                    fld(
                        "maybe",
                        FieldType::Conditional {
                            condition_field: "flag".to_string(),
                            condition_value: 1,
                            condition_op: ConditionOp::Eq,
                            fields: vec![fld("x", FieldType::UInt8)],
                        },
                    ),
                ),
                fld("after", FieldType::UInt8),
            ];
            let data = [flag, 1, 2, 3, 4, 5, 6, 7];
            apply_fields(&reg, &fields, &data).unwrap()
        };
        let skipped = maybe(0);
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[1].name, "after");
        assert_eq!(skipped[1].offset, 1);
        let taken = maybe(1);
        assert_eq!(taken.len(), 3);
        assert_eq!(taken[1].name, "x");
        assert_eq!(taken[1].offset, 5);
        assert_eq!(taken[2].name, "after");
        assert_eq!(taken[2].offset, 6);

        let negative = vec![positioned("0 - 1", fld("bad", FieldType::UInt8))];
        let err = apply_fields(&reg, &negative, &[0u8; 4]).unwrap_err();
        assert!(
            matches!(&err, TemplateError::ExpressionError(m) if m.contains("negative offset -1")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_signed_pointer_and_enum_display_use_field_width() {
        let mut reg = TemplateRegistry::new();
        reg.register(tmpl("Tgt", vec![fld("marker", FieldType::UInt8)]));
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x77, 0x77];
        let result = apply_fields(
            &reg,
            &[fld("p", pointer_to("Tgt", FieldType::Int32))],
            &data,
        )
        .unwrap();
        assert_eq!(result[0].display_value, "-> 0xFFFFFFFF (Tgt)");
        assert_eq!(result[0].children.len(), 0);

        let negative = FieldType::Enum {
            backing_type: Box::new(FieldType::Int8),
            values: vec![("neg".to_string(), -1)],
        };
        let result = apply_fields(&reg, &[fld("e", negative)], &[0xFF]).unwrap();
        assert_eq!(result[0].display_value, "neg (-1, 0xFF)");

        let wide = FieldType::Enum {
            backing_type: Box::new(FieldType::UInt64),
            values: vec![("neg".to_string(), -1)],
        };
        let result = apply_fields(&reg, &[fld("e", wide)], &[0xFF; 8]).unwrap();
        assert_eq!(
            result[0].display_value,
            "neg (18446744073709551615, 0xFFFFFFFFFFFFFFFF)"
        );
    }
}
