import json
import unittest
from tools.hosted.source_intake import aggregate, verified_refresh_population
from tools.release_contract.contracts import ContractError

class SourceIntakeAggregateTests(unittest.TestCase):
    def fixture(self):
        return {'EvaluatedAt':'2026-11-15T00:00:00Z','SourceCount':2,'CurrentCount':1,
            'IntakeDecisions':[{'ID':'private-source-a','State':'current','Reason':''},
                {'ID':'private-source-b','State':'quarantined','Reason':'private-provider-secret'}],
            'Reconciliation':[{'ID':'private-source-a','State':'current'},
                {'ID':'private-source-b','State':'quarantined'}]}

    def test_failed_intake_has_safe_aggregate_without_copying_private_fields(self):
        value=aggregate(self.fixture(),{'private-source-a','private-source-b'},1794700800,2)
        self.assertFalse(value['all_active_current'])
        self.assertEqual(value['blocked_reason_counts'],{'other_intake_gate':1})
        self.assertNotIn('private-',json.dumps(value))
        self.assertEqual(value['current_sources'],1)

    def test_counts_and_evaluation_are_not_success_flags(self):
        private=self.fixture();private['CurrentCount']=2
        self.assertFalse(aggregate(private,{'private-source-a','private-source-b'},1794700800,2)['all_active_current'])
        for clock,count in ((1794700801,2),(1794700800,3)):
            with self.assertRaises(ContractError):aggregate(private,{'private-source-a','private-source-b'},clock,count)

    def test_refresh_can_checkpoint_only_reconciled_current_sources_after_a_publisher_outage(self):
        expected = {'private-source-a', 'private-source-b'}
        private = self.fixture()
        private['IntakeDecisions'][1].update(State='stale', Reason='publication_expired')
        private['Reconciliation'][1].update(State='missing', Reason='payload_missing')
        state = {'Version': 2, 'EvaluatedAt': private['EvaluatedAt'], 'Sources': [{'ID': 'private-source-a'}]}
        self.assertTrue(verified_refresh_population(private, state, expected))
        self.assertFalse(aggregate(private, expected, 1794700800, 2)['all_active_current'])
        self.assertFalse(verified_refresh_population(private, dict(state, EvaluatedAt='changed'), expected))
        for sources in ([], state['Sources'] * 2, [{'ID': 'private-source-b'}], [{'ID': 'outside'}]):
            self.assertFalse(verified_refresh_population(private, dict(state, Sources=sources), expected))
        for key in ('IntakeDecisions', 'Reconciliation'):
            for rows in (private[key][:1], private[key] + private[key][:1]):
                self.assertFalse(verified_refresh_population(dict(private, **{key: rows}), state, expected))
        private['IntakeDecisions'][1].update(Reason='reviewed_fixture_certification_required')
        self.assertFalse(verified_refresh_population(private, state, expected))
