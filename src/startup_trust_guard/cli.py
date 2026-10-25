"""Command line interface with value-free diagnostic output."""
import argparse
import sys
import json
from . import configcheck, scan, trust


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, 'error: invalid command line arguments\n')


def main(argv=None):
    parser = SafeArgumentParser(prog='startup-trust-guard')
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check')
    check.add_argument('directory', nargs='?', default='.')
    check.add_argument('--json', action='store_true')
    config = commands.add_parser('config-check')
    config.add_argument('--codex-config')
    config.add_argument('--claude-settings')
    config.add_argument('--json', action='store_true')
    baseline = commands.add_parser('baseline').add_subparsers(dest='action', required=True)
    baseline.add_parser('save').add_argument('--out')
    baseline.add_parser('show').add_argument('--path')
    trusted = commands.add_parser('trust').add_subparsers(dest='action', required=True)
    trusted.add_parser('add').add_argument('file')
    trusted.add_parser('list')
    args = parser.parse_args(argv)
    try:
        if args.command == 'check':
            result = scan.scan(args.directory)
        elif args.command == 'config-check':
            result, unused = configcheck.check(args.codex_config, args.claude_settings)
        elif args.command == 'baseline':
            if args.action == 'save':
                configcheck.save(args.out)
                print('baseline saved')
            else:
                data = trust.load_json(args.path or trust.state_path('baseline.json'), {})
                # Show only the known schema: never echo arbitrary persisted values.
                clean = {}
                for kind in ('codex', 'claude'):
                    if kind in data:
                        clean[kind] = {group: {configcheck.redact(key): '<fingerprint>' if group == 'urls' else True
                                              for key in data[kind].get(group, {})}
                                       for group in ('servers', 'urls')}
                print(json.dumps(clean, indent=2))
            return 0
        else:
            if args.action == 'add':
                trust.add(args.file)
                print('file added to trust list')
            else:
                print(configcheck.redact(json.dumps(trust.trusted_files(), indent=2)))
            return 0
        # Names can themselves contain token-like strings; redact them as well.
        if args.json:
            print(configcheck.redact(json.dumps(result)))
        else:
            if result.get('message'):
                print(result['message'])
            elif not result['findings']:
                print('no findings')
            for finding in result['findings']:
                print(configcheck.redact('{severity} {file}: {rules}'.format(
                    rules=', '.join(finding['reasons']), **finding)))
        return int(any(f['severity'] in ('HIGH', 'CRITICAL') for f in result['findings']))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('error: unable to read or process input')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
