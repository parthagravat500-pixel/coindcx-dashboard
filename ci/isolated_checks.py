"""Run the owned application's regression suite only after isolation checks.

No arbitrary repository URL, command, generated code, or production credential is
accepted. This is regression testing, not a general hostile-code sandbox or bounty
discovery. GitHub's disposable VM is an additional boundary around the container.
"""
import json
import os
from pathlib import Path
import sys
import time
import unittest


def policy_checks(state):
    """Pure fail-closed checks; values are collected before app/test imports."""
    cpu = state.get('cpu', '').split()
    cpu_ok = (len(cpu) == 2 and all(x.isdigit() for x in cpu)
              and 0 < int(cpu[0]) <= 2 * int(cpu[1]) and int(cpu[1]) > 0)
    def bounded(name, maximum):
        value = str(state.get(name, ''))
        return value.isdigit() and 0 < int(value) <= maximum
    return {
        'non_root': isinstance(state.get('uid'), int) and state['uid'] > 0,
        'loopback_only': state.get('interfaces') == ['lo'],
        'read_only_source': state.get('read_only_source') is True,
        'no_capabilities': state.get('capabilities') == 0,
        'no_new_privileges': state.get('no_new_privileges') == '1',
        'seccomp_filter': state.get('seccomp') == '2',
        'bounded_cpu': cpu_ok,
        'bounded_memory': bounded('memory', 1024 * 1024 * 1024),
        'bounded_processes': bounded('pids', 128),
        'no_credential_environment': state.get('credential_environment') is False,
        'no_docker_socket': state.get('docker_socket') is False,
    }


def inspect_isolation():
    proc = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    cgroup = Path('/sys/fs/cgroup')
    return {
        'uid': os.getuid(),
        'interfaces': sorted(x.name for x in Path('/sys/class/net').iterdir()),
        'read_only_source': bool(os.statvfs('/app').f_flag & os.ST_RDONLY),
        'capabilities': int(proc['CapEff'].strip(), 16),
        'no_new_privileges': proc['NoNewPrivs'].strip(),
        'seccomp': proc['Seccomp'].strip(),
        'cpu': (cgroup / 'cpu.max').read_text().strip(),
        'memory': (cgroup / 'memory.max').read_text().strip(),
        'pids': (cgroup / 'pids.max').read_text().strip(),
        'credential_environment': any(value and any(word in key.upper() for word in ('TOKEN', 'PASSWORD', 'SECRET', 'API_KEY')) for key, value in os.environ.items()),
        'docker_socket': Path('/var/run/docker.sock').exists(),
    }


def main():
    start = time.monotonic()
    try:
        checks = policy_checks(inspect_isolation())
    except (OSError, KeyError, ValueError):
        print(json.dumps({'kind': 'isolation', 'status': 'unverified', 'tests_started': False}))
        return 2
    print(json.dumps({'kind': 'isolation', 'checks': checks}), flush=True)
    if not all(checks.values()):
        print(json.dumps({'kind': 'isolation', 'status': 'failed', 'tests_started': False}))
        return 2
    suite = unittest.defaultTestLoader.discover('/app', pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun > 0
    print(json.dumps({
        'kind': 'regression', 'status': 'passed' if passed else 'failed',
        'tests_run': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'skipped': len(result.skipped),
        'seconds': round(time.monotonic() - start, 2),
        'scope': 'ScopeGuard owned-code tests; real loopback HTTP and synthetic fixtures',
        'external_targets_tested': 0, 'bounty_bugs_confirmed': 0,
        'paid_model_calls': 0,
    }), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
