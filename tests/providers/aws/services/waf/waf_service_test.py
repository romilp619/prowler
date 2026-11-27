from unittest.mock import patch

import botocore
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from prowler.providers.aws.services.waf.waf_service import (
    WAF,
    Predicate,
    Rule,
    RuleGroup,
    WAFRegional,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking WAF Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": "my-web-acl-id", "Name": "my-web-acl"},
            ]
        }
    if operation_name == "ListResourcesForWebACL":
        return {
            "ResourceArns": [
                "alb-arn",
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [
                    {
                        "RuleId": "my-rule-id",
                        "Type": "REGULAR",
                    },
                    {
                        "RuleId": "my-rule-group-id",
                        "Type": "GROUP",
                    },
                ],
            }
        }
    if operation_name == "ListRules":
        return {
            "Rules": [
                {
                    "RuleId": "my-rule-id",
                    "Name": "my-rule",
                },
            ]
        }
    if operation_name == "GetRule":
        return {
            "Rule": {
                "RuleId": "my-rule-id",
                "Name": "my-rule",
                "Predicates": [
                    {
                        "Negated": False,
                        "Type": "IPMatch",
                        "DataId": "my-data-id",
                    }
                ],
            }
        }
    if operation_name == "ListRuleGroups":
        return {
            "RuleGroups": [
                {
                    "RuleGroupId": "my-rule-group-id",
                    "Name": "my-rule-group",
                },
            ]
        }
    if operation_name == "ListActivatedRulesInRuleGroup":
        return {
            "ActivatedRules": [
                {
                    "RuleId": "my-rule-id",
                },
            ]
        }
    if operation_name == "GetLoggingConfiguration":
        return {
            "LoggingConfiguration": {
                "ResourceArn": "arn:aws:waf:123456789012:webacl/my-web-acl-id",
                "LogDestinationConfigs": [
                    "arn:aws:firehose:us-east-1:123456789012:deliverystream/my-firehose"
                ],
                "RedactedFields": [],
                "ManagedByFirewallManager": False,
            }
        }
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_WAF_Service:
    # Test WAF Global Service
    def test_service_global(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        assert waf.service == "waf"

    # Test WAF Global Client
    def test_client_global(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        for regional_client in waf.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAF"

    # Test WAF Global Session
    def test__get_session___global(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        assert waf.session.__class__.__name__ == "Session"

    # Test WAF Global List Rules
    def test_list_rules(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        assert waf.rules

    # Test WAF Global Get Rule
    def test_get_rule(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        rule_arn = (
            f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id"
        )
        assert waf.rules == {
            rule_arn: Rule(
                arn=rule_arn,
                id="my-rule-id",
                name="my-rule",
                region=AWS_REGION_US_EAST_1,
                predicates=[
                    Predicate(negated=False, type="IPMatch", data_id="my-data-id")
                ],
            )
        }

    # Test WAF Global List Rule Groups
    def test_list_rule_groups(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        assert waf.rule_groups

    # Test WAF Global Get Rule Groups
    def test_get_rule_groups(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        rule_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id"
        assert waf.rule_groups == {
            rule_arn: RuleGroup(
                arn=f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id",
                id="my-rule-group-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule-group",
                rules=[
                    Rule(
                        arn=f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                        id="my-rule-id",
                        region=AWS_REGION_US_EAST_1,
                        name="my-rule",
                        predicates=[
                            Predicate(
                                negated=False, type="IPMatch", data_id="my-data-id"
                            )
                        ],
                        tags=[],
                    )
                ],
            )
        }

    # Test WAF Global List Web ACLs
    def test_list_web_acls_waf_global(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert len(waf.web_acls) == 1
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups

    # Test WAF Global Get Web ACL
    def test_get_web_acl(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAF(aws_provider)
        waf_arn = f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules == [
            Rule(
                arn=f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                id="my-rule-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule",
                predicates=[
                    Predicate(negated=False, type="IPMatch", data_id="my-data-id")
                ],
                tags=[],
            )
        ]
        assert waf.web_acls[waf_arn].rule_groups == [
            RuleGroup(
                arn=f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id",
                id="my-rule-group-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule-group",
                rules=[
                    Rule(
                        arn=f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                        id="my-rule-id",
                        region=AWS_REGION_US_EAST_1,
                        name="my-rule",
                        predicates=[
                            Predicate(
                                negated=False, type="IPMatch", data_id="my-data-id"
                            )
                        ],
                        tags=[],
                    )
                ],
            )
        ]

    # Test WAFRegional Describe Web ACLs Resources
    def test_list_resources_for_web_acl(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert len(waf.web_acls) == 1
        assert len(waf.web_acls[waf_arn].albs) == 1
        assert "alb-arn" in waf.web_acls[waf_arn].albs

    # Test WAFRegional Service
    def test_service_regional(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        assert waf.service == "waf-regional"

    # Test WAFRegional Client
    def test_client_regional(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        for regional_client in waf.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFRegional"

    # Test WAFRegional Session
    def test__get_session___regional(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        assert waf.session.__class__.__name__ == "Session"

    # Test WAFRegional List Rules
    def test_list_regional_rules(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        assert waf.rules

    # Test WAFRegional Get Rule
    def test_get_regional_rule(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        rule_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id"
        assert waf.rules == {
            rule_arn: Rule(
                arn=rule_arn,
                id="my-rule-id",
                name="my-rule",
                region=AWS_REGION_US_EAST_1,
                predicates=[
                    Predicate(negated=False, type="IPMatch", data_id="my-data-id")
                ],
            )
        }

    # Test WAFRegional List Rule Groups
    def test_list_regional_rule_groups(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        assert waf.rule_groups

    # Test WAFRegional Get Rule Groups
    def test_get_regional_rule_groups(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups
        rule_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id"
        assert waf.rule_groups == {
            rule_arn: RuleGroup(
                arn=f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id",
                id="my-rule-group-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule-group",
                rules=[
                    Rule(
                        arn=f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                        id="my-rule-id",
                        region=AWS_REGION_US_EAST_1,
                        name="my-rule",
                        predicates=[
                            Predicate(
                                negated=False, type="IPMatch", data_id="my-data-id"
                            )
                        ],
                        tags=[],
                    )
                ],
            )
        }

    # Test WAFRegional List Web ACLs
    def test_list__regionalweb_acls_waf(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert len(waf.web_acls) == 1
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules
        assert waf.web_acls[waf_arn].rule_groups

    # Test WAFRegional Get Web ACL
    def test_get_regional_web_acl(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        waf = WAFRegional(aws_provider)
        waf_arn = f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/my-web-acl-id"
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"
        assert waf.web_acls[waf_arn].rules == [
            Rule(
                arn=f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                id="my-rule-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule",
                predicates=[
                    Predicate(negated=False, type="IPMatch", data_id="my-data-id")
                ],
                tags=[],
            )
        ]
        assert waf.web_acls[waf_arn].rule_groups == [
            RuleGroup(
                arn=f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/my-rule-group-id",
                id="my-rule-group-id",
                region=AWS_REGION_US_EAST_1,
                name="my-rule-group",
                rules=[
                    Rule(
                        arn=f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/my-rule-id",
                        id="my-rule-id",
                        region=AWS_REGION_US_EAST_1,
                        name="my-rule",
                        predicates=[
                            Predicate(
                                negated=False, type="IPMatch", data_id="my-data-id"
                            )
                        ],
                        tags=[],
                    )
                ],
            )
        ]


# ListRules, ListRuleGroups, ListWebACLs and ListActivatedRulesInRuleGroup return at
# most 100 items. A NextMarker means another page remains and must be requested back.
SERVICE_CASES = [
    pytest.param(WAF, "waf", id="global"),
    pytest.param(WAFRegional, "waf-regional", id="regional"),
]


def _new_service(service_class):
    return service_class(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))


def _inventory_client(service):
    if isinstance(service, WAFRegional):
        return service.regional_clients[AWS_REGION_US_EAST_1]
    return service.client


def _resource_arn(service_name, resource_type, resource_id):
    return (
        f"arn:aws:{service_name}:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
        f"{resource_type}/{resource_id}"
    )


def _invoke_regional_or_global(service, method_name):
    method = getattr(service, method_name)
    if isinstance(service, WAFRegional):
        method(_inventory_client(service))
    else:
        method()


class Test_WAF_Pagination:
    """Pagination of WAF Classic list calls for the global and regional clients."""

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_rules_includes_later_pages(self, service_class, service_name):
        service = _new_service(service_class)
        service.rules = {}
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_rules",
                {
                    "Rules": [{"RuleId": "rule-1", "Name": "rule-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_response(
                "list_rules",
                {"Rules": [{"RuleId": "rule-2", "Name": "rule-two"}]},
                {"NextMarker": "page-two"},
            )
            _invoke_regional_or_global(service, "_list_rules")
            stubber.assert_no_pending_responses()

        assert sorted(service.rules) == sorted(
            [
                _resource_arn(service_name, "rule", "rule-1"),
                _resource_arn(service_name, "rule", "rule-2"),
            ]
        )
        assert service.rules[_resource_arn(service_name, "rule", "rule-2")].name == (
            "rule-two"
        )

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_rule_groups_includes_later_pages(self, service_class, service_name):
        service = _new_service(service_class)
        service.rule_groups = {}
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_rule_groups",
                {
                    "RuleGroups": [{"RuleGroupId": "group-1", "Name": "group-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_response(
                "list_rule_groups",
                {"RuleGroups": [{"RuleGroupId": "group-2", "Name": "group-two"}]},
                {"NextMarker": "page-two"},
            )
            _invoke_regional_or_global(service, "_list_rule_groups")
            stubber.assert_no_pending_responses()

        assert sorted(service.rule_groups) == sorted(
            [
                _resource_arn(service_name, "rulegroup", "group-1"),
                _resource_arn(service_name, "rulegroup", "group-2"),
            ]
        )
        assert (
            service.rule_groups[
                _resource_arn(service_name, "rulegroup", "group-2")
            ].name
            == "group-two"
        )

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_activated_rules_includes_later_pages(
        self, service_class, service_name
    ):
        service = _new_service(service_class)
        first_arn = _resource_arn(service_name, "rule", "rule-1")
        second_arn = _resource_arn(service_name, "rule", "rule-2")
        service.rules = {
            first_arn: Rule(
                arn=first_arn,
                id="rule-1",
                region=AWS_REGION_US_EAST_1,
                name="rule-one",
            ),
            second_arn: Rule(
                arn=second_arn,
                id="rule-2",
                region=AWS_REGION_US_EAST_1,
                name="rule-two",
            ),
        }
        rule_group = RuleGroup(
            arn=_resource_arn(service_name, "rulegroup", "group-1"),
            id="group-1",
            region=AWS_REGION_US_EAST_1,
            name="group-one",
        )
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_activated_rules_in_rule_group",
                {
                    "ActivatedRules": [{"Priority": 1, "RuleId": "rule-1"}],
                    "NextMarker": "page-two",
                },
                {"RuleGroupId": "group-1"},
            )
            stubber.add_response(
                "list_activated_rules_in_rule_group",
                {"ActivatedRules": [{"Priority": 2, "RuleId": "rule-2"}]},
                {"RuleGroupId": "group-1", "NextMarker": "page-two"},
            )
            service._list_activated_rules_in_rule_group(rule_group)
            stubber.assert_no_pending_responses()

        assert [rule.id for rule in rule_group.rules] == ["rule-1", "rule-2"]

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_web_acls_includes_later_pages(self, service_class, service_name):
        service = _new_service(service_class)
        service.web_acls = {}
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_web_acls",
                {
                    "WebACLs": [{"WebACLId": "acl-1", "Name": "acl-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_response(
                "list_web_acls",
                {"WebACLs": [{"WebACLId": "acl-2", "Name": "acl-two"}]},
                {"NextMarker": "page-two"},
            )
            _invoke_regional_or_global(service, "_list_web_acls")
            stubber.assert_no_pending_responses()

        assert sorted(service.web_acls) == sorted(
            [
                _resource_arn(service_name, "webacl", "acl-1"),
                _resource_arn(service_name, "webacl", "acl-2"),
            ]
        )
        assert (
            service.web_acls[_resource_arn(service_name, "webacl", "acl-2")].name
            == "acl-two"
        )

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_web_acls_filters_audited_resources_on_every_page(
        self, service_class, service_name
    ):
        service = _new_service(service_class)
        service.web_acls = {}
        service.audit_resources = ["acl-2"]
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_web_acls",
                {
                    "WebACLs": [{"WebACLId": "acl-1", "Name": "acl-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_response(
                "list_web_acls",
                {"WebACLs": [{"WebACLId": "acl-2", "Name": "acl-two"}]},
                {"NextMarker": "page-two"},
            )
            _invoke_regional_or_global(service, "_list_web_acls")
            stubber.assert_no_pending_responses()

        assert list(service.web_acls) == [
            _resource_arn(service_name, "webacl", "acl-2")
        ]

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_rules_keeps_pages_read_before_an_error(
        self, service_class, service_name
    ):
        service = _new_service(service_class)
        service.rules = {}
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_rules",
                {
                    "Rules": [{"RuleId": "rule-1", "Name": "rule-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_client_error(
                "list_rules",
                service_error_code="Throttling",
                expected_params={"NextMarker": "page-two"},
            )
            _invoke_regional_or_global(service, "_list_rules")
            stubber.assert_no_pending_responses()

        assert list(service.rules) == [_resource_arn(service_name, "rule", "rule-1")]

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_rules_continues_past_an_empty_page_when_a_marker_remains(
        self, service_class, service_name
    ):
        service = _new_service(service_class)
        service.rules = {}
        client = _inventory_client(service)

        with Stubber(client) as stubber:
            stubber.add_response(
                "list_rules",
                {
                    "Rules": [{"RuleId": "rule-1", "Name": "rule-one"}],
                    "NextMarker": "page-two",
                },
                {},
            )
            stubber.add_response(
                "list_rules",
                {"Rules": [], "NextMarker": "page-three"},
                {"NextMarker": "page-two"},
            )
            stubber.add_response(
                "list_rules",
                {"Rules": [{"RuleId": "rule-2", "Name": "rule-two"}]},
                {"NextMarker": "page-three"},
            )
            _invoke_regional_or_global(service, "_list_rules")
            stubber.assert_no_pending_responses()

        assert sorted(service.rules) == sorted(
            [
                _resource_arn(service_name, "rule", "rule-1"),
                _resource_arn(service_name, "rule", "rule-2"),
            ]
        )

    @pytest.mark.parametrize("service_class,service_name", SERVICE_CASES)
    @mock_aws
    def test_list_rules_stops_when_next_marker_repeats(
        self, service_class, service_name
    ):
        """A marker that never changes must not walk the list forever."""
        service = _new_service(service_class)
        service.rules = {}
        client = _inventory_client(service)
        calls = []

        def list_rules(**kwargs):
            calls.append(kwargs)
            if len(calls) > 2:
                raise AssertionError("pagination did not stop")
            return {
                "Rules": [{"RuleId": "rule-1", "Name": "rule-one"}],
                "NextMarker": "loop-forever",
            }

        client.list_rules = list_rules

        with patch(
            "prowler.providers.aws.services.waf.waf_service.logger"
        ) as mock_logger:
            _invoke_regional_or_global(service, "_list_rules")

        assert len(calls) == 2
        assert list(service.rules) == [_resource_arn(service_name, "rule", "rule-1")]
        error_messages = [
            str(call.args[0]) for call in mock_logger.error.call_args_list
        ]
        if client.can_paginate("list_rules"):
            assert any("PaginationError" in message for message in error_messages)
        else:
            assert any(
                "pagination loop detected" in message for message in error_messages
            )
