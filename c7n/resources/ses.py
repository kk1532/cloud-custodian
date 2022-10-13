import logging

from c7n.filters import (
    Filter, ValueFilter, AgeFilter)
from c7n.utils import type_schema
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from datetime import datetime, timedelta

log = logging.getLogger('custodian.ses')


@resources.register('ses-statistics')
class SesStatistics(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'ses'
        enum_spec = ('get_send_statistics', 'SendDataPoints', None)
        name = id = 'Timestamp'
        date = 'Timestamp'
        metrics_namespace = 'AWS/SES'


@SesStatistics.filter_registry.register('agg-stats')
class SesAggStats(ValueFilter):
    """This filter aggregates the individual timestamp stats into single report.

    :example:

    .. code-block:: yaml

            policies:
              - name: ses-aggregated-send-statsd
                resource: ses-statistics
                filters:
                  - type: agg-stats
    """

    schema = type_schema('agg-stats', rinherit=ValueFilter.schema)

    permissions = ("ses:GetSendStatistics",)

    def process(self, resources, event=None):
        results = []
        resource_counter = {'DeliveryAttempts': 0,
                            'Bounces': 0,
                            'Complaints': 0,
                            'Rejects': 0,
                            'BounceRate': 0}
        for r in resources:
            if r:
                resource_counter['DeliveryAttempts'] += r['DeliveryAttempts']
                resource_counter['Bounces'] += r['Bounces']
                resource_counter['Complaints'] += r['Complaints']
                resource_counter['Rejects'] += r['Rejects']
        resource_counter['BounceRate'] = round(
            (resource_counter['Bounces'] /
             resource_counter['DeliveryAttempts']) * 100)
        results.append(resource_counter)

        return results


@SesStatistics.filter_registry.register('age')
class SesAgeStats(AgeFilter):
    """Filters SES send statistics based on age (in days)

    :example:

    .. code-block:: yaml

            policies:
              - name: ses-age-based-send-statsd
                resource: ses-statistics
                filters:
                  - type: age
                    days: 2
                    op: ge
    """

    schema = type_schema(
        'age', days={'type': 'number'},
        op={'$ref': '#/definitions/filters_common/comparison_operators'})

    date_attribute = 'Timestamp'


@SesStatistics.filter_registry.register('consecutive-stats')
class SesConsecutiveStats(Filter):
    """Filters consecutive days on statistic as days based. By default 2 days.

    :example:

    .. code-block:: yaml

            policies:
              - name: ses-send-statsd
                resource: ses-statistics
                filters:
                  - type: consecutive-stats
                    days: 2
    """
    schema = type_schema('consecutive-stats', days={'type': 'number', 'minimum': 2},
                         required=['days'])

    permissions = ("ses:GetSendStatistics",)

    def process(self, resources, event=None):
        account = self.manager.config.account_id
        data = []
        tmp_data = {}
        check_days = self.data.get('days', 2)
        utcnow = datetime.utcnow()
        expected_dates = set()

        for days in range(1, check_days + 1):
            expected_dates.add((utcnow - timedelta(days=days)).strftime('%Y-%m-%d'))

        for r in resources:
            if r['Timestamp']:
                ts = r['Timestamp'].strftime('%Y-%m-%d')
                ts_set = {ts}
                if ts_set.issubset(expected_dates):
                    try:
                        if ts not in tmp_data.keys():
                            tmp_data.update({ts: {'DeliveryAttempts': 0,
                                                  'Bounces': 0,
                                                  'Complaints': 0,
                                                  'Rejects': 0}})
                        tmp_data[ts]['DeliveryAttempts'] += r['DeliveryAttempts']
                        tmp_data[ts]['Bounces'] += r['Bounces']
                        tmp_data[ts]['Complaints'] += r['Complaints']
                        tmp_data[ts]['Rejects'] += r['Rejects']
                    except KeyError as e:
                        raise e
        data.append(tmp_data)
        results = []
        for d in data:
            if d:
                for k, v in d.items():
                    d[k]['BounceRate'] = int(
                        round((d[k]['Bounces'] / d[k]['DeliveryAttempts']) * 100))
                    d[k]['Date'] = k
                    d[k]['OwnerId'] = account
                    results.append(d[k])
        return results
