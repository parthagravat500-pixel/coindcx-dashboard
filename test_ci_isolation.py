import unittest
from ci.isolated_checks import policy_checks


class IsolationPolicyTests(unittest.TestCase):
    def state(self):
        return {'uid': 65532, 'interfaces': ['lo'], 'read_only_source': True,
                'capabilities': 0, 'no_new_privileges': '1', 'seccomp': '2',
                'cpu': '200000 100000', 'memory': str(1024 ** 3), 'pids': '128',
                'credential_environment': False, 'docker_socket': False}

    def test_configured_limits_pass(self):
        self.assertTrue(all(policy_checks(self.state()).values()))

    def test_each_missing_condition_fails_closed(self):
        for key in self.state():
            with self.subTest(key=key):
                state = self.state()
                del state[key]
                self.assertFalse(all(policy_checks(state).values()))

    def test_unsafe_settings_fail_closed(self):
        variants = {'uid': 0, 'interfaces': ['eth0', 'lo'], 'read_only_source': False,
                    'capabilities': 1, 'no_new_privileges': '0', 'seccomp': '0',
                    'cpu': 'max 100000', 'memory': 'max', 'pids': 'max',
                    'credential_environment': True, 'docker_socket': True}
        for key, value in variants.items():
            with self.subTest(key=key):
                self.assertFalse(all(policy_checks({**self.state(), key: value}).values()))

    def test_over_budget_and_malformed_cpu_fail(self):
        for value in ('300000 100000', '0 100000', '1 0', '-1 100000', '', 'x', '1 2 3'):
            with self.subTest(cpu=value):
                self.assertFalse(policy_checks({**self.state(), 'cpu': value})['bounded_cpu'])
        self.assertFalse(policy_checks({**self.state(), 'memory': str(2 * 1024 ** 3)})['bounded_memory'])
        self.assertFalse(policy_checks({**self.state(), 'pids': '129'})['bounded_processes'])
