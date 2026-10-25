"""Configuration inspection. Values are never included in findings."""
import hashlib
import json
import re
from pathlib import Path
from .trust import load_json, state_path


def redact(text):
    return re.sub(r'[A-Za-z0-9_-]{20,}', '<redacted>', str(text))


def parse_config(path):
    path = Path(path)
    text = path.read_text(encoding='utf-8')
    if path.suffix == '.json':
        data = json.loads(text)
    else:
        try:
            import tomllib
        except ImportError:
            data = parse_toml(text)
        else:
            data = tomllib.loads(text)
    if not isinstance(data, dict):
        raise ValueError('configuration must be an object')
    return data


def parse_toml(text):
    """Use the bundled CPython stdlib TOML parser on Python 3.9/3.10."""
    from ._toml_parser import loads
    return loads(text)


def config_paths(codex=None, claude=None):
    return [Path(codex).expanduser() if codex else Path.home() / '.codex/config.toml',
            Path(claude).expanduser() if claude else Path.home() / '.claude/settings.json']


def inspect_config(data, label):
    findings, snapshot = [], {'servers': {}, 'urls': {}}
    def walk(node, prefix=''):
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            location = prefix + '.' + key if prefix else key
            if key in ('mcp_servers', 'mcpServers') and isinstance(value, dict):
                for name in value:
                    entry = location + '.' + name
                    snapshot['servers'][entry] = True
                    findings.append({'file': label, 'severity': 'HIGH', 'reasons': ['mcp-server: ' + redact(entry)]})
            if key.lower() in ('base_url', 'anthropic_base_url') or (key.lower() == 'url' and 'model_provider' in prefix):
                # Fingerprint rather than store URLs, which may contain embedded credentials.
                snapshot['urls'][location] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
                findings.append({'file': label, 'severity': 'HIGH', 'reasons': ['url-override: ' + redact(location)]})
            if ('approval' in location.lower() or 'permission' in location.lower()) and (value is False or str(value).lower() in ('never', 'none', 'bypasspermissions', 'bypass', 'dontask', 'true')):
                findings.append({'file': label, 'severity': 'HIGH', 'reasons': ['approvals-disabled: ' + redact(location)]})
            walk(value, location)
    walk(data)
    return findings, snapshot


def check(codex=None, claude=None, compare=True):
    findings, snapshot, found = [], {}, False
    for kind, path in zip(('codex', 'claude'), config_paths(codex, claude)):
        if not path.exists():
            continue
        found = True
        items, state = inspect_config(parse_config(path), kind)
        findings.extend(items)
        snapshot[kind] = state
    if compare:
        baseline = load_json(state_path('baseline.json'), None)
        if baseline is not None:
            for kind in sorted(set(baseline) | set(snapshot)):
                for group in ('servers', 'urls'):
                    old = baseline.get(kind, {}).get(group, {})
                    new = snapshot.get(kind, {}).get(group, {})
                    for key in sorted(set(old) | set(new)):
                        change = 'ADDED' if key not in old else 'REMOVED' if key not in new else 'CHANGED' if old[key] != new[key] else None
                        if change:
                            findings.append({'file': kind, 'severity': 'CRITICAL', 'reasons': [change + ': ' + redact(key)]})
    return {'findings': findings, 'message': '' if found else 'no config files found'}, snapshot


def save(out=None):
    unused, snapshot = check(compare=False)
    target = Path(out).expanduser() if out else state_path('baseline.json')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return target
