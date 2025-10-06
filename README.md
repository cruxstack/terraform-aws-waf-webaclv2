# terraform-aws-waf-webaclv2

Terraform module to configure WAF Web ACL V2 for Application Load Balancer or
Cloudfront distribution.

Supported WAF v2 components:

- [AWS-managed rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
- Associating WAFv2 ACL with one or more Application Load Balancers (ALB)
- Blocking IP Sets
- Rate limiting IPs (and optional scope down statements)
- Byte Match statements
- Geo set statements
- Logical Statements (AND, OR, NOT)
- Size constraint statements
- Label Match statements
- Regex Match statements
- Regex Pattern Match statements
- Custom responses
- Attach Custom Rule Groups

## Usage


```hcl
module "waf" {
  source = "github.com/cruxstack/terraform-aws-waf-webaclv2?ref=v1.x.x"

  name_prefix = "test-waf-setup"
  alb_arn     = module.alb.arn

  scope = "REGIONAL"

  create_alb_association = true

  allow_default_action = true # set to allow if not specified

  visibility_config = {
    metric_name = "test-waf-setup-waf-main-metrics"
  }

  rules = [
    {
      name     = "AWSManagedRulesCommonRuleSet-rule-1"
      priority = "1"

      override_action = "none"

      visibility_config = {
        metric_name                = "AWSManagedRulesCommonRuleSet-metric"
      }

      managed_rule_group_statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        rule_action_overrides = [
          {
            action_to_use = {
              count = {}
            }

            name = "SizeRestrictions_QUERYSTRING"
          },
          {
            action_to_use = {
              count = {}
            }

            name = "SizeRestrictions_BODY"
          },
          {
            action_to_use = {
              count = {}
            }

            name = "GenericRFI_QUERYARGUMENTS"
          }
        ]
      }
    },
    {
      name     = "AWSManagedRulesKnownBadInputsRuleSet-rule-2"
      priority = "2"

      override_action = "count"

      visibility_config = {
        metric_name = "AWSManagedRulesKnownBadInputsRuleSet-metric"
      }

      managed_rule_group_statement = {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    },
    {
      name     = "AWSManagedRulesPHPRuleSet-rule-3"
      priority = "3"

      override_action = "none"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "AWSManagedRulesPHPRuleSet-metric"
        sampled_requests_enabled   = false
      }

      managed_rule_group_statement = {
        name        = "AWSManagedRulesPHPRuleSet"
        vendor_name = "AWS"
      }
    },
    ### Byte Match Rule example
    # Refer to https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#byte-match-statement
    # for all of the options available.
    # Additional examples available in the examples directory
    {
      name     = "ByteMatchRule-4"
      priority = "4"

      action = "count"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "ByteMatchRule-metric"
        sampled_requests_enabled   = false
      }

      byte_match_statement = {
        field_to_match = {
          uri_path = "{}"
        }
        positional_constraint = "STARTS_WITH"
        search_string         = "/path/to/match"
        priority              = 0
        type                  = "NONE"
      }
    },
    ### Geo Match Rule example
    {
      name     = "GeoMatchRule-5"
      priority = "5"

      action = "allow"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "GeoMatchRule-metric"
        sampled_requests_enabled   = false
      }

      geo_match_statement = {
        country_codes = ["NL", "GB", "US"]
      }
    },
    ### IP Set Rule example
    {
      name     = "IpSetRule-6"
      priority = "6"

      action = "allow"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "IpSetRule-metric"
        sampled_requests_enabled   = false
      }

      ip_set_reference_statement = {
        arn = "arn:aws:wafv2:eu-west-1:111122223333:regional/ipset/ip-set-test/a1bcdef2-1234-123a-abc0-1234a5bc67d8"
      }
    },
    ### IP Rate Based Rule example
    {
      name     = "IpRateBasedRule-7"
      priority = "7"

      action = "block"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "IpRateBasedRule-metric"
        sampled_requests_enabled   = false
      }

      rate_based_statement = {
        limit              = 100
        aggregate_key_type = "IP"
        # Optional scope_down_statement to refine what gets rate limited
        scope_down_statement = {
          not_statement = {
            byte_match_statement = {
              field_to_match = {
                uri_path = "{}"
              }
              positional_constraint = "STARTS_WITH"
              search_string         = "/path/to/match"
              priority              = 0
              type                  = "NONE"
            }
          }
        }
      }
    },
    ### NOT rule example (can be applied to byte_match, geo_match, and ip_set rules)
    {
      name     = "NotByteMatchRule-8"
      priority = "8"

      action = "count"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "NotByteMatchRule-metric"
        sampled_requests_enabled   = false
      }

      not_statement = {
        byte_match_statement = {
          field_to_match = {
            uri_path = "{}"
          }
          positional_constraint = "STARTS_WITH"
          search_string         = "/path/to/match"
          priority              = 0
          type                  = "NONE"
        }
      }
    },
    ### Regex Match Rule example
    {
      name     = "RegexMatchRule-9"
      priority = "9"

      action = "allow"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "RegexMatchRule-metric"
        sampled_requests_enabled   = false
      }

      byte_match_statement = {
          field_to_match = {
            uri_path = "{}"
          }
          regex_string         = "/foo/"
          priority              = 0
          type                  = "NONE"
        }
    ### Attach Custom Rule Group example
    {
      name     = "CustomRuleGroup-1"
      priority = "9"

      override_action = "none"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "CustomRuleGroup-metric"
        sampled_requests_enabled   = false
      }

      rule_group_reference_statement = {
        arn = "arn:aws:wafv2:eu-west-1:111122223333:regional/rulegroup/rulegroup-test/a1bcdef2-1234-123a-abc0-1234a5bc67d8"
      }
    ### Regex Match Rule example
    {
      name     = "RegexMatchRule-9"
      priority = "9"

      action = "allow"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "RegexMatchRule-metric"
        sampled_requests_enabled   = false
      }

      byte_match_statement = {
          field_to_match = {
            uri_path = "{}"
          }
          regex_string         = "/foo/"
          priority              = 0
          type                  = "NONE"
        }
    ### Attach Custom Rule Group example
    {
      name     = "CustomRuleGroup-1"
      priority = "9"

      override_action = "none"

      visibility_config = {
        cloudwatch_metrics_enabled = false
        metric_name                = "CustomRuleGroup-metric"
        sampled_requests_enabled   = false
      }

      rule_group_reference_statement = {
        arn = "arn:aws:wafv2:eu-west-1:111122223333:regional/rulegroup/rulegroup-test/a1bcdef2-1234-123a-abc0-1234a5bc67d8"
      }
    },
    ### Size constraint Rule example
    # Refer to https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#size-constraint-statement
    # for all of the options available.
    # Additional examples available in the examples directory
    {
      name     = "BodySizeConstraint"
      priority = 0
      size_constraint_statement = {
        field_to_match = {
          body = "{}"
        }
        comparison_operator = "GT"
        size                = 8192
        priority            = 0
        type                = "NONE"
      }

      action = "count"

      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "BodySizeConstraint"
        sampled_requests_enabled   = true
      }
    },
    ### Regex Pattern Set Reference Rule example
    # Refer to https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#regex-pattern-set-reference-statement
    # for all of the options available.
    # Additional examples available in the examples directory
    {
      name = "MatchRegexRule-1"
      priority = "1"

      action = "none"

      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "RegexBadBotsUserAgent-metric"
        sampled_requests_enabled   = false
      }

      # You need to previously create you regex pattern
      # Refer to https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_regex_pattern_set
      # for all of the options available.
      regex_pattern_set_reference_statement = {
        arn       = aws_wafv2_regex_pattern_set.example.arn
        field_to_match = {
          single_header = {
            name = "user-agent"
          }
        }
        priority  = 0
        type      = "LOWERCASE" # The text transformation type
      }
    }
  ]

  tags = {
    "Name" = "test-waf-setup"
    "Env"  = "test"
  }
}
```

### Cloudfront configuration

```hcl
provider "aws" {
  alias = "us-east"

  version = ">= 4.44.0"
  region  = "us-east-1"
}

module "waf" {
  source = "github.com/cruxstack/terraform-aws-waf-webaclv2?ref=v1.x.x"

  name_prefix = "test-waf-setup-cloudfront"
  scope = "CLOUDFRONT"
  create_alb_association = false

  // ...
}
```

## Logging configuration

When you enable logging configuration for WAFv2. Remember to follow the naming
convention defined in [AWS's documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html).
Importantly, make sure that Amazon Kinesis Data Firehose is using a name
starting with the prefix `aws-waf-logs-`.

## Acknowledgment

This module was initially derived from [uMotif’s terraform-aws-waf-webaclv2](https://github.com/umotif-public/terraform-aws-waf-webaclv2).
Significant modifications and refactoring have been made in this repository.

