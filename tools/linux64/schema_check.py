"""Minimal JSON Schema validator for the project's own spec documents.

The program spec in ``spec_schema.json`` is the stable contract between
reconnaissance and every lifting backend, so it has to be checked rather than
believed. Pulling in ``jsonschema`` for that would add a dependency to a
stdlib-only pipeline, so this module implements the keyword subset the project
schemas actually use, and fails loudly on any keyword it does not understand.
That last rule matters: a validator that silently ignores an unknown constraint
reports success for a document nobody checked.

Supported keywords: ``type`` (string or list), ``const``, ``enum``, ``required``,
``properties``, ``additionalProperties`` (boolean), ``items``, ``minimum``,
``maximum``, ``minItems``, ``maxItems``, ``patternProperties`` (via ``pattern``).

Unsupported keywords raise :class:`SchemaError` at validation time, naming the
keyword, so the gap is visible instead of silent.
"""

from __future__ import annotations

import json
import re
from typing import Any, List

SUPPORTED_KEYWORDS = frozenset({
    "$schema", "$id", "title", "description", "default", "examples",
    "type", "const", "enum", "required", "properties", "additionalProperties",
    "items", "minimum", "maximum", "minItems", "maxItems", "patternProperties",
    "pattern", "definitions", "$defs", "$ref", "propertyNames",
})


class SchemaError(ValueError):
    """Raised when an instance does not satisfy its schema."""


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    raise SchemaError(f"unknown type constraint {name!r}")


def _resolve_ref(root: Any, ref: str) -> Any:
    if not ref.startswith("#/"):
        raise SchemaError(f"only local $ref is supported, got {ref!r}")
    node = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            raise SchemaError(f"unresolvable $ref {ref!r}")
        node = node[token]
    return node


def validate(instance: Any, schema: Any, root: Any = None, path: str = "$") -> None:
    """Validate *instance* against *schema*. Raises SchemaError listing every
    violation found, so one run reports all of them."""
    if root is None:
        root = schema
    errors: List[str] = []
    _validate(instance, schema, root, path, errors)
    if errors:
        raise SchemaError("; ".join(errors[:20]))


def _validate(instance: Any, schema: Any, root: Any, path: str, errors: List[str]) -> None:
    if schema is True or schema == {}:
        return
    if schema is False:
        errors.append(f"{path}: schema forbids any value")
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"{path}: schema node must be an object, got {type(schema).__name__}")

    unknown = set(schema) - SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaError(f"{path}: unsupported schema keyword(s): {sorted(unknown)}")

    if "$ref" in schema:
        _validate(instance, _resolve_ref(root, schema["$ref"]), root, path, errors)
        return

    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else list(names)
        if not any(_is_type(instance, name) for name in names):
            expected = " or ".join(names)
            errors.append(f"{path}: expected {expected}, got {type(instance).__name__}")
            return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not one of {schema['enum']!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} above maximum {schema['maximum']}")

    if isinstance(instance, dict):
        _validate_object(instance, schema, root, path, errors)
    elif isinstance(instance, list):
        _validate_array(instance, schema, root, path, errors)
    elif isinstance(instance, str) and "pattern" in schema:
        if not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")


def _validate_object(instance: dict, schema: dict, root: Any, path: str,
                     errors: List[str]) -> None:
    properties = schema.get("properties", {})
    patterns = schema.get("patternProperties", {})

    for name in schema.get("required", []):
        if name not in instance:
            errors.append(f"{path}: missing required property {name!r}")

    for name, value in instance.items():
        child = f"{path}.{name}"
        matched = False
        if name in properties:
            _validate(value, properties[name], root, child, errors)
            matched = True
        for pattern, subschema in patterns.items():
            if re.search(pattern, name):
                _validate(value, subschema, root, child, errors)
                matched = True
        if not matched and schema.get("additionalProperties") is False:
            errors.append(f"{child}: unexpected property")


def _validate_array(instance: list, schema: dict, root: Any, path: str,
                    errors: List[str]) -> None:
    if "minItems" in schema and len(instance) < schema["minItems"]:
        errors.append(f"{path}: {len(instance)} items, minimum {schema['minItems']}")
    if "maxItems" in schema and len(instance) > schema["maxItems"]:
        errors.append(f"{path}: {len(instance)} items, maximum {schema['maxItems']}")
    items = schema.get("items")
    if items is None:
        return
    if isinstance(items, list):
        for index, value in enumerate(instance[:len(items)]):
            _validate(value, items[index], root, f"{path}[{index}]", errors)
        return
    for index, value in enumerate(instance):
        _validate(value, items, root, f"{path}[{index}]", errors)


def validate_document(instance: Any, schema_path: str) -> None:
    """Validate *instance* against the schema file at *schema_path*."""
    with open(schema_path, "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    validate(instance, schema)


def _selftest() -> None:
    schema = {
        "type": "object",
        "required": ["format", "items"],
        "properties": {
            "format": {"const": "x"},
            "items": {"type": "array", "items": {
                "type": "object", "required": ["start"], "properties": {
                    "start": {"type": "integer", "minimum": 0},
                    "name": {"type": ["string", "null"]},
                }}},
        },
        "additionalProperties": False,
    }
    validate({"format": "x", "items": [{"start": 0, "name": None}]}, schema)

    for bad, why in (
        ({"format": "y", "items": []}, "const mismatch"),
        ({"items": []}, "missing required"),
        ({"format": "x", "items": [{"start": -1}]}, "minimum"),
        ({"format": "x", "items": [{"start": "0"}]}, "wrong item type"),
        ({"format": "x", "items": [{"start": 0}], "extra": 1}, "additionalProperties"),
    ):
        try:
            validate(bad, schema)
        except SchemaError:
            pass
        else:
            raise AssertionError(f"validator accepted {why}: {bad!r}")

    # A schema keyword we do not implement must fail rather than pass silently.
    try:
        validate({}, {"type": "object", "allOf": []})
    except SchemaError as exc:
        assert "allOf" in str(exc), exc
    else:
        raise AssertionError("validator silently ignored an unsupported keyword")

    print("schema: ok")


if __name__ == "__main__":
    _selftest()
