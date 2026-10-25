# startup-trust-guard

A website can download AGENTS.md or CLAUDE.md into Downloads, where an agent
may later treat it as trusted instructions. Agent configuration can also be
changed to add an MCP server, redirect a provider URL, or disable approvals.
This tool reports startup directory and config baseline risks before you start.

Python 3.9+; standard library only, no runtime or build dependencies, no network.
Install with `python3 -m pip install --no-build-isolation .`, or run directly:

```sh
PYTHONPATH=src python3 -m startup_trust_guard.cli check . --json
startup-trust-guard check ~/Downloads
startup-trust-guard config-check
startup-trust-guard config-check --codex-config ./config.toml --claude-settings ./settings.json
startup-trust-guard baseline save
startup-trust-guard baseline save --out ./baseline.json
startup-trust-guard baseline show
startup-trust-guard baseline show --path ./baseline.json
startup-trust-guard trust add ./AGENTS.md
startup-trust-guard trust list
```

The scan reads AGENTS.md, CLAUDE.md, GEMINI.md and .cursorrules at the top
level and directly inside .claude/ and .cursor/, plus .claude/settings.json
as configuration. It does not recurse further. Git-tracked and explicitly
trusted files are OK unless suspicious content wins. Downloads paths and
recent untracked files are HIGH. Older untracked files are conservatively
HIGH too. Suspicious shell pipelines, provider overrides, approval bypasses,
destructive commands, credential references and remote MCP definitions are
CRITICAL. Symlinks are HIGH and are never followed into credential files.
Content matching is heuristic: quoted examples can trigger findings, and
obfuscated instructions may evade detection.

Config checks read only ~/.codex/config.toml and ~/.claude/settings.json, or
the explicitly supplied alternatives. MCP entries, provider URL overrides,
and disabled approvals are HIGH. MCP name and provider URL changes against
the default baseline are CRITICAL (ADDED, REMOVED or CHANGED). Baselines
store URL SHA-256 fingerprints instead of raw URLs because URLs can contain
secrets. `baseline show` displays keys and fingerprint markers, never values.
Python 3.9/3.10 use a bundled copy of the MIT-licensed CPython standard
library TOML parser; Python 3.11+ uses tomllib directly. No external TOML
package is required.

Findings contain names, severities and rule names only, never file contents
or configuration values. Long token-like strings in names are redacted too.
No credential files are opened. Normal checks are read-only. `trust add`
explicitly writes the trust registry under ~/.config/startup-trust-guard/;
`baseline save` explicitly writes its baseline there or at --out.
Custom baselines can be shown with --path; automatic config comparison uses
the default baseline. No files are written elsewhere by the tool.

Exit codes: **0** means no HIGH/CRITICAL findings (including no config files),
**1** means findings require review, **2** means a usage, input or I/O error.
`check --json` returns an object with `dir` and `findings`; `config-check`
also supports --json. Configuration values are never included in either format.

This tool does not block an agent, quarantine or delete files, or auto-fix
configuration. agent-guard guards tool calls; mcp-audit audits MCP servers.
startup-trust-guard guards the startup directory and config baseline.

Run tests from the project root:

```sh
python3 -m unittest discover -s tests -v
```
