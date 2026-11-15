import json
import unittest
from tools.hosted.source_intake import aggregate
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
