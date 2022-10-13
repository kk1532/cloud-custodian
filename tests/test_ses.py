# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from .common import BaseTest


class TestSesStatistics(BaseTest):

    def test_ses_base_stats(self):
        factory = self.replay_flight_data("test_ses_base_stats")
        p = self.load_policy(
            {
                "name": "test-ses",
                "resource": "ses-statistics",
            },
            config={'region': 'us-west-2'},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 116)

    def test_ses_agg_stats(self):
        factory = self.replay_flight_data('test_ses_base_stats')
        p = self.load_policy({
            'name': 'ses-agg-stats',
            'resource': 'aws.ses-statistics',
            'filters': [{"type": "agg-stats"}]},
            config={'region': 'us-west-2'},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_ses_age(self):
        factory = self.replay_flight_data('test_ses_base_stats')
        p = self.load_policy({
            'name': 'ses-stats-age-based',
            'resource': 'aws.ses-statistics',
            'filters': [{"type": "age", "days": 1, "op": "le"}]},
            config={'region': 'us-west-2'},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 4)

    def test_ses_consecutive_stats(self):
        factory = self.replay_flight_data('test_ses_base_stats')
        p = self.load_policy({
            'name': 'ses-consecutive-stats',
            'resource': 'aws.ses-statistics',
            'filters': [{"type": "consecutive-stats", "days": 2}]},
            config={'region': 'us-west-2'},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 2)
        for r in resources:
            self.assertTrue(r['Date'])
            self.assertTrue(r['OwnerId'])

