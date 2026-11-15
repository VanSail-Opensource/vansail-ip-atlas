import copy
from hashlib import sha256
import unittest

from tools.atlas_contracts.config import ContractError, ROOT, load_yaml, validate_schema, validate_sources
from tools.atlas_contracts.policy import capability_report, caida_discovery_supported, static_issues, utc


class ReplacementCandidateTests(unittest.TestCase):
    def setUp(self):
        self.config = load_yaml(ROOT / 'configs/sources.yaml')
        self.ids = {'ffraud-ip', 'routeviews-wide-rib', 'ripe-mrt-rrc18', 'caida-asrel2', 'rpki-client-vrps'}
        self.config['sources'] = [s for s in self.config['sources'] if s['id'] in self.ids]

    def test_active_replacements_have_exact_assets_but_no_current_facts(self):
        self.assertEqual({s['id'] for s in self.config['sources']}, self.ids)
        validate_schema('sources', self.config)
        validate_sources(self.config)
        for source in self.config['sources']:
            with self.subTest(source=source['id']):
                self.assertEqual(source['admission'], 'active')
                self.assertEqual(source['fixture']['status'], 'passed')
                self.assertTrue(source['fixture']['schema_observed'])
                self.assertIs(source['fixture']['synthetic'], False)
                payload = (ROOT / source['fixture']['path']).read_bytes()
                self.assertEqual(sha256(payload).hexdigest(), source['fixture']['sha256'])
                self.assertEqual(static_issues(source, ROOT), [])
        report = capability_report(self.config, utc('2026-11-15T14:00:00Z'), ROOT)
        self.assertEqual(report['active_count'], 5)
        self.assertEqual(report['current_count'], 0)
        self.assertEqual(report['dataset_attributions'], [])
        self.assertTrue(all(not row['families'] for row in report['capabilities']))

    def test_deactivated_replacements_cannot_contribute_facts_or_credits(self):
        for source in self.config['sources']:
            source['admission'] = 'candidate'
        report = capability_report(self.config, utc('2026-11-15T14:00:00Z'), ROOT)
        self.assertEqual(report['active_count'], 0)
        self.assertEqual(report['current_count'], 0)
        self.assertEqual(report['dataset_attributions'], [])
        self.assertTrue(all(not row['families'] for row in report['capabilities']))

    def test_public_storage_schema_five_rejects_old_schema(self):
        validate_schema('sources', self.config)
        for version in (3, 4, 6):
            invalid = copy.deepcopy(self.config)
            invalid['build']['storage']['schema_version'] = version
            with self.subTest(version=version), self.assertRaises(ContractError):
                validate_schema('sources', invalid)

    def test_caida_discovery_requires_exact_reviewed_clock_and_assets(self):
        source = next(s for s in self.config['sources'] if s['id'] == 'caida-asrel2')
        self.assertTrue(caida_discovery_supported(source))
        for section, key, value in [
            ('download', 'url', 'https://publicdata.caida.org/datasets/as-relationships/serial-2/20261101.as-rel2.txt.bz2'),
            ('download', 'format', 'text'), ('discovery', 'no_guessing', False),
            ('discovery', 'requires_exact_file', False), ('discovery', 'filename_pattern', '.*'),
            ('discovery', 'index_url', 'https://example.com/'), ('discovery', 'ordering', 'http-date'),
            ('publication_proof', 'field', 'filename'), ('publication_proof', 'locator', 'https://example.com/'),
            ('parser', 'version', 2),
        ]:
            invalid = copy.deepcopy(self.config)
            altered = next(s for s in invalid['sources'] if s['id'] == 'caida-asrel2')
            altered[section][key] = value
            self.assertFalse(caida_discovery_supported(altered))
            with self.subTest(section=section, key=key), self.assertRaises(ContractError):
                validate_sources(invalid)

    def test_ffraud_global_credit_retains_entire_original_mit_notice(self):
        source = next(s for s in self.config['sources'] if s['id'] == 'ffraud-ip')
        original = (ROOT / 'fixtures/source-certification/notices/FFraud-data.txt').read_text()
        self.assertEqual(source['license']['attribution']['text'], ' '.join(original.split()))
        self.assertEqual(source['license']['distribution'], 'allow')
        self.assertEqual(source['license']['status'], 'reviewed')


if __name__ == '__main__':
    unittest.main()
