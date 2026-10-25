"""Explicit, local trust records."""
import json
from pathlib import Path


def state_path(name):
    return Path.home() / '.config' / 'startup-trust-guard' / name


def load_json(path, default):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def trusted_files():
    data = load_json(state_path('trusted.json'), [])
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise ValueError('invalid trust file')
    return data


def add(file):
    path = Path(file).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError('trust target must be a file')
    entries = trusted_files()
    if str(path) not in entries:
        entries.append(str(path))
    out = state_path('trusted.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, indent=2) + '\n', encoding='utf-8')
    return path
