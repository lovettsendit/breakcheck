from dataclasses import dataclass
import copy
import json
from typing import Mapping

_SPECS = [{'allow_unknown': False, 'class_name': 'ReplaySnippet', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'args_source': ['literal', 'refused']}, 'fields': [{'default_kind': 'required', 'name': 'snippet_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'code'}, {'default_kind': 'required', 'name': 'args_source'}, {'default_kind': 'none', 'name': 'reason_code'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'Observation', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'kind': ['value', 'exception', 'timeout']}, 'fields': [{'default_kind': 'required', 'name': 'kind'}, {'default_kind': 'required', 'name': 'payload'}, {'default_kind': 'none', 'name': 'exception_class'}, {'default_kind': 'none', 'name': 'duration_ms'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'Comparison', 'closed_mapping_fields': {'detail': {'enum_fields': {'reason_code': ['EQUAL', 'KIND_MISMATCH', 'EXCEPTION_CLASS', 'VALUE_MISMATCH', 'FLOAT_MISMATCH', 'MISSING_KEY', 'LENGTH_MISMATCH']}, 'json_pointer_fields': ['path'], 'nullable_fields': ['path'], 'required_fields': ['reason_code', 'path', 'old_summary', 'new_summary', 'policy']}}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED']}, 'fields': [{'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'required', 'name': 'detail'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'Finding', 'closed_mapping_fields': {}, 'conditional_list_rules': [{'cases': {'CHANGED': {'max_items': 2, 'min_items': 1}, 'IDENTICAL': {'max_items': 0, 'min_items': 0}, 'NOT_EXERCISED': {'max_items': 1, 'min_items': 1}}, 'discriminator_field': 'verdict', 'field': 'suggested_action'}], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED', 'NOT_EXERCISED']}, 'fields': [{'default_kind': 'required', 'name': 'finding_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'none', 'name': 'old'}, {'default_kind': 'none', 'name': 'new'}, {'default_kind': 'required', 'name': 'repro'}, {'default_kind': 'required', 'name': 'suggested_action'}, {'default_kind': 'none', 'name': 'reason_code'}, {'default_kind': 'required', 'name': 'comparison'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}, 'suggested_action': {'required_fields': ['kind', 'argument']}}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'Report', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {'schema_version': 1}, 'enum_fields': {}, 'fields': [{'default_kind': 'required', 'name': 'package'}, {'default_kind': 'required', 'name': 'current_version'}, {'default_kind': 'required', 'name': 'new_version'}, {'default_kind': 'required', 'name': 'coverage'}, {'default_kind': 'required', 'name': 'findings'}, {'default_kind': 'required', 'name': 'witnesses'}, {'default_kind': 'required', 'name': 'summary'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {'findings': {'sort_fields': ['finding_id']}}}, {'allow_unknown': False, 'class_name': 'Environment', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'EnvironmentPair', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}}, {'allow_unknown': False, 'class_name': 'UsageManifest', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}}]

def _plain(value):
    if hasattr(value, 'to_dict') and callable(value.to_dict):
        return _plain(value.to_dict())
    if isinstance(value, dict): return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [_plain(v) for v in value]
    return value

def _sort_key(data, names):
    return tuple(json.dumps(_plain(data.get(name)), sort_keys=True, separators=(',', ':'), default=repr) for name in names)

def _pointer(value):
    return isinstance(value, str) and (value == '' or value.startswith('/'))

def _nested_mapping(value, config, where):
    if not isinstance(value, dict) or set(value) != set(config['required_fields']): raise TypeError(where + ' must be a closed mapping')
    for name, choices in config['enum_fields'].items():
        if value[name] not in choices: raise ValueError(where + '.' + name + ' has an invalid enum value')
    for name in config['required_fields']:
        if name in config['nullable_fields'] and value[name] is None: continue
        if name in config['json_pointer_fields'] and not _pointer(value[name]): raise ValueError(where + '.' + name + ' is not a JSON pointer')
    return copy.deepcopy(value)

def _validate(data, spec):
    names = {field['name'] for field in spec['fields']} | set(spec['constant_fields'])
    if set(data) - names: raise TypeError('unknown fields: ' + ','.join(sorted(set(data) - names)))
    for name, choices in spec['enum_fields'].items():
        if data[name] not in choices: raise ValueError(name + ' has an invalid enum value')
    for name, config in spec['closed_mapping_fields'].items():
        data[name] = _nested_mapping(data[name], config, name)
    for name, config in spec['ordered_mapping_list_fields'].items():
        if not isinstance(data[name], list): raise TypeError(name + ' must be a list')
        required = set(config['required_fields'])
        for item in data[name]:
            if not isinstance(item, dict) or set(item) != required: raise TypeError(name + ' contains an open mapping')
    for name in spec['sort_list_fields']:
        if not isinstance(data[name], list): raise TypeError(name + ' must be a list')
    for rule in spec['conditional_list_rules']:
        bounds = rule['cases'].get(data.get(rule['discriminator_field']))
        if bounds is not None and not bounds['min_items'] <= len(data[rule['field']]) <= bounds['max_items']:
            raise ValueError(rule['field'] + ' cardinality is invalid')

def _init_record(self, values, spec):
    data = copy.deepcopy(dict(values))
    names = {field['name'] for field in spec['fields']} | set(spec['constant_fields'])
    unknown = set(data) - names
    if unknown: raise TypeError('unknown fields: ' + ','.join(sorted(unknown)))
    for field in spec['fields']:
        name, kind = field['name'], field['default_kind']
        if name not in data:
            if kind == 'required': raise TypeError(name + ' is required')
            data[name] = {'zero': 0, 'empty': '', 'false': False, 'none': None, 'empty_list': []}[kind]
    for name, value in spec['constant_fields'].items():
        if name in data and data[name] != value: raise ValueError(name + ' disagrees with constant')
        data[name] = copy.deepcopy(value)
    _validate(data, spec)
    for name in names: object.__setattr__(self, name, data[name])

def _record_dict(self, spec):
    names = [field['name'] for field in spec['fields']] + list(spec['constant_fields'])
    data = {name: _plain(getattr(self, name)) for name in names}
    for name, config in spec['sort_list_fields'].items(): data[name] = sorted(data[name], key=lambda item: _sort_key(item, config['sort_fields']))
    return data

@dataclass(frozen=True, init=False)
class ReplaySnippet:
    snippet_id: object = None
    api: object = None
    call_sites: object = None
    code: object = None
    args_source: object = None
    reason_code: object = None

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'ReplaySnippet', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'args_source': ['literal', 'refused']}, 'fields': [{'default_kind': 'required', 'name': 'snippet_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'code'}, {'default_kind': 'required', 'name': 'args_source'}, {'default_kind': 'none', 'name': 'reason_code'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'ReplaySnippet', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'args_source': ['literal', 'refused']}, 'fields': [{'default_kind': 'required', 'name': 'snippet_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'code'}, {'default_kind': 'required', 'name': 'args_source'}, {'default_kind': 'none', 'name': 'reason_code'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class Observation:
    kind: object = None
    payload: object = None
    exception_class: object = None
    duration_ms: object = None

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'Observation', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'kind': ['value', 'exception', 'timeout']}, 'fields': [{'default_kind': 'required', 'name': 'kind'}, {'default_kind': 'required', 'name': 'payload'}, {'default_kind': 'none', 'name': 'exception_class'}, {'default_kind': 'none', 'name': 'duration_ms'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'Observation', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'kind': ['value', 'exception', 'timeout']}, 'fields': [{'default_kind': 'required', 'name': 'kind'}, {'default_kind': 'required', 'name': 'payload'}, {'default_kind': 'none', 'name': 'exception_class'}, {'default_kind': 'none', 'name': 'duration_ms'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class Comparison:
    verdict: object = None
    detail: object = None

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'Comparison', 'closed_mapping_fields': {'detail': {'enum_fields': {'reason_code': ['EQUAL', 'KIND_MISMATCH', 'EXCEPTION_CLASS', 'VALUE_MISMATCH', 'FLOAT_MISMATCH', 'MISSING_KEY', 'LENGTH_MISMATCH']}, 'json_pointer_fields': ['path'], 'nullable_fields': ['path'], 'required_fields': ['reason_code', 'path', 'old_summary', 'new_summary', 'policy']}}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED']}, 'fields': [{'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'required', 'name': 'detail'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'Comparison', 'closed_mapping_fields': {'detail': {'enum_fields': {'reason_code': ['EQUAL', 'KIND_MISMATCH', 'EXCEPTION_CLASS', 'VALUE_MISMATCH', 'FLOAT_MISMATCH', 'MISSING_KEY', 'LENGTH_MISMATCH']}, 'json_pointer_fields': ['path'], 'nullable_fields': ['path'], 'required_fields': ['reason_code', 'path', 'old_summary', 'new_summary', 'policy']}}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED']}, 'fields': [{'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'required', 'name': 'detail'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class Finding:
    finding_id: object = None
    api: object = None
    call_sites: object = None
    verdict: object = None
    old: object = None
    new: object = None
    repro: object = None
    suggested_action: object = None
    reason_code: object = None
    comparison: object = None

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'Finding', 'closed_mapping_fields': {}, 'conditional_list_rules': [{'cases': {'CHANGED': {'max_items': 2, 'min_items': 1}, 'IDENTICAL': {'max_items': 0, 'min_items': 0}, 'NOT_EXERCISED': {'max_items': 1, 'min_items': 1}}, 'discriminator_field': 'verdict', 'field': 'suggested_action'}], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED', 'NOT_EXERCISED']}, 'fields': [{'default_kind': 'required', 'name': 'finding_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'none', 'name': 'old'}, {'default_kind': 'none', 'name': 'new'}, {'default_kind': 'required', 'name': 'repro'}, {'default_kind': 'required', 'name': 'suggested_action'}, {'default_kind': 'none', 'name': 'reason_code'}, {'default_kind': 'required', 'name': 'comparison'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}, 'suggested_action': {'required_fields': ['kind', 'argument']}}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'Finding', 'closed_mapping_fields': {}, 'conditional_list_rules': [{'cases': {'CHANGED': {'max_items': 2, 'min_items': 1}, 'IDENTICAL': {'max_items': 0, 'min_items': 0}, 'NOT_EXERCISED': {'max_items': 1, 'min_items': 1}}, 'discriminator_field': 'verdict', 'field': 'suggested_action'}], 'constant_fields': {}, 'enum_fields': {'verdict': ['IDENTICAL', 'CHANGED', 'NOT_EXERCISED']}, 'fields': [{'default_kind': 'required', 'name': 'finding_id'}, {'default_kind': 'required', 'name': 'api'}, {'default_kind': 'required', 'name': 'call_sites'}, {'default_kind': 'required', 'name': 'verdict'}, {'default_kind': 'none', 'name': 'old'}, {'default_kind': 'none', 'name': 'new'}, {'default_kind': 'required', 'name': 'repro'}, {'default_kind': 'required', 'name': 'suggested_action'}, {'default_kind': 'none', 'name': 'reason_code'}, {'default_kind': 'required', 'name': 'comparison'}], 'ordered_mapping_list_fields': {'call_sites': {'required_fields': ['file', 'line']}, 'suggested_action': {'required_fields': ['kind', 'argument']}}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class Report:
    package: object = None
    current_version: object = None
    new_version: object = None
    coverage: object = None
    findings: object = None
    witnesses: object = None
    summary: object = None
    schema_version: object = None

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'Report', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {'schema_version': 1}, 'enum_fields': {}, 'fields': [{'default_kind': 'required', 'name': 'package'}, {'default_kind': 'required', 'name': 'current_version'}, {'default_kind': 'required', 'name': 'new_version'}, {'default_kind': 'required', 'name': 'coverage'}, {'default_kind': 'required', 'name': 'findings'}, {'default_kind': 'required', 'name': 'witnesses'}, {'default_kind': 'required', 'name': 'summary'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {'findings': {'sort_fields': ['finding_id']}}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'Report', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {'schema_version': 1}, 'enum_fields': {}, 'fields': [{'default_kind': 'required', 'name': 'package'}, {'default_kind': 'required', 'name': 'current_version'}, {'default_kind': 'required', 'name': 'new_version'}, {'default_kind': 'required', 'name': 'coverage'}, {'default_kind': 'required', 'name': 'findings'}, {'default_kind': 'required', 'name': 'witnesses'}, {'default_kind': 'required', 'name': 'summary'}], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {'findings': {'sort_fields': ['finding_id']}}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class Environment:

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'Environment', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'Environment', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class EnvironmentPair:

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'EnvironmentPair', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'EnvironmentPair', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])

@dataclass(frozen=True, init=False)
class UsageManifest:

    def __init__(self, **values):
        _init_record(self, values, {'allow_unknown': False, 'class_name': 'UsageManifest', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def to_dict(self):
        return _record_dict(self, {'allow_unknown': False, 'class_name': 'UsageManifest', 'closed_mapping_fields': {}, 'conditional_list_rules': [], 'constant_fields': {}, 'enum_fields': {}, 'fields': [], 'ordered_mapping_list_fields': {}, 'sort_fields': [], 'sort_list_fields': {}})

    def sort_key(self):
        return _sort_key(self.to_dict(), [])


def canonical_json(value):
    return json.dumps(_plain(value), sort_keys=True, separators=(',', ':'))


@dataclass(frozen=True)
class ArtifactEnvelope:
    """Immutable validated view of a closed schema-2 artifact."""

    schema_version: int
    artifact_kind: str
    payload: dict
    payload_sha256: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ArtifactEnvelope":
        from breakcheck.schema import validate_artifact

        artifact = validate_artifact(value)
        return cls(
            schema_version=artifact["schema_version"],
            artifact_kind=artifact["artifact_kind"],
            payload=copy.deepcopy(artifact["payload"]),
            payload_sha256=artifact["payload_sha256"],
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "artifact_kind": self.artifact_kind,
            "payload": copy.deepcopy(self.payload),
            "payload_sha256": self.payload_sha256,
        }
