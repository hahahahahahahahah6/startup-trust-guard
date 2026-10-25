"""Read instruction files without disclosing their contents."""
import re
import subprocess
import time
from pathlib import Path
from .trust import trusted_files

RULES = [
    ('shell-pipeline', r'\|\s*(?:/bin/)?(?:ba)?sh\b'),
    ('base-url-override', r'\b(?:base_url|ANTHROPIC_BASE_URL)\b["\x27]?\s*[:=]'),
    ('bypass-safety', r'\b(?:ignore|disregard|bypass)\b[^\n.]{0,100}\b(?:safety|permissions?|approvals?)\b'),
    ('destructive-shell', r'\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+[~/]'),
    ('privileged-command', r'\bsudo\b'),
    ('credential-access', r'\$HOME/\.codex/auth\.json|~/\.claude\.json|\bid_rsa\b|\b(?:ANTHROPIC|OPENAI)_API_KEY\b'),
    ('remote-mcp-server', r'(?:mcp_servers|mcpServers)[\s\S]*https?://'),
]


def suspicious_rules(content):
    return [name for name, pattern in RULES if re.search(pattern, content, re.I)]


def git_tracked(directory, relative):
    try:
        result = subprocess.run(['git', '-C', str(directory), 'ls-files', '-z', '--', relative],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        return result.returncode == 0 and bool(result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan(directory):
    directory = Path(directory).expanduser().resolve(strict=True)
    if not directory.is_dir():
        raise ValueError('scan target must be a directory')
    whitelist = set(trusted_files())
    names = ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules']
    for folder in ('.claude', '.cursor'):
        names.extend(folder + '/' + name for name in ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules'])
    names.append('.claude/settings.json')
    findings = []
    for name in names:
        path = directory / name
        if not path.exists():
            if path.is_symlink():
                raise OSError('broken instruction symlink')
            continue
        if not path.is_file():
            raise OSError('instruction path is not a file')
        resolved = path.resolve()
        # Never follow instruction links into arbitrary files (including credentials).
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != directory.parent):
            findings.append({'file': name, 'severity': 'HIGH', 'reasons': ['instruction-symlink']})
            continue
        content = path.read_text(encoding='utf-8')
        reasons = suspicious_rules(content)
        if name == '.claude/settings.json':
            from .configcheck import parse_config, inspect_config
            config_findings, unused = inspect_config(parse_config(path), name)
            reasons.extend(rule for finding in config_findings for rule in finding['reasons'])
        if reasons:
            severity = 'CRITICAL'
        elif str(resolved) in whitelist or git_tracked(directory, name):
            severity, reasons = 'OK', ['trusted']
        elif any(p.lower() == 'downloads' for p in resolved.parts) or time.time() - path.stat().st_mtime <= 30 * 86400:
            severity, reasons = 'HIGH', ['untrusted-download']
        else:
            severity, reasons = 'HIGH', ['untrusted-instruction']
        findings.append({'file': name, 'severity': severity, 'reasons': sorted(set(reasons))})
    return {'dir': str(directory), 'findings': findings}
