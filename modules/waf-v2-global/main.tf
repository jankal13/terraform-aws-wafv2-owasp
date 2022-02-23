#
# This is our WAF ACL with each rule defined and prioritized accordingly.
#
resource aws_wafv2_web_acl waf_v2_acl {
  name        = "${var.wafv2_prefix}-generic-owasp-acl"
  description = "WAF for public domain"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
    metric_name                 = replace("${var.wafv2_prefix}genericowaspacl", "/[^0-9A-Za-z]/", "")
    sampled_requests_enabled    = var.sampled_requests_enabled
  }

  # Whitelist rule sets
  rule {
      name                          = "${var.wafv2_prefix}-whitelist"
      priority                      = 10

      action {
        allow {}
      }
      
      statement {
        rule_group_reference_statement {
          arn                       = aws_wafv2_rule_group.whitelist.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
      }
  }

  rule {
      name                          = "${var.wafv2_prefix}-whitelist"
      priority                      = 20

      action {
        count {}
      }
      
      statement {
        rule_group_reference_statement {
          arn                       = aws_wafv2_rule_group.blacklist.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}blacklist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
      }
  }
      
  tags = var.tags
}


#########################################################################################################
## Rulegroup Whitelist


resource aws_wafv2_rule_group whitelist {
  name        = "${var.wafv2_prefix}-rulegroup-whitelist"
  description = "A rule group containing all whitelisted statements"
  scope       = "CLOUDFRONT"
  capacity    = 700 
  

  visibility_config {
    cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
    metric_name = replace("${var.wafv2_prefix}rulegroupwhitelist", "/[^0-9A-Za-z]/", "")
    sampled_requests_enabled    = var.sampled_requests_enabled
  }

  rule {
    name      = "${var.wafv2_prefix}-generic-match-whitelisted-ips"
    priority  = 10

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.whitelisted_elastic_ips.arn
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelistedips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  }

  rule {
    name      = "${var.wafv2_prefix}-generic-match-whitelisted-elastic-ips"
    priority  = 20

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.whitelisted_ips.arn
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelistedelasticips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  }


  rule {
    name = "${var.wafv2_prefix}-generic-whitelisted-user-agent-header"
    priority  = 30

    action {
      allow {}
    }


    statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = var.whitelisted_user_agent_header
            
            field_to_match {
              single_query_argument {
                name = "user-agent"
              }
            }

            text_transformation {
              priority            = 1
              type                = "NONE"
            }
          }

    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}whitelisteduseragent", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }
  
}



#########################################################################################################
## Rulegroup Blacklist

resource aws_wafv2_rule_group blacklist {
  name        = "${var.wafv2_prefix}-rulegroup-blacklist"
  description = "A rule group containing all blacklisted statements"
  scope       = "CLOUDFRONT"
  capacity    = 1000

  visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}rulegroupblacklist", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
  }

  rule {
    name      = "${var.wafv2_prefix}-generic-mitigate-sqli"
    priority  = 10

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          sqli_match_statement {
            field_to_match {
              body {}
            }

             text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }

            text_transformation {
              priority = 3
              type     = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {

            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }


      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericmitigatesqli", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-bad-auth-tokens"
    priority  = 20

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
            
            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "example-session-id"
            
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectbadauthtokens", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-mitigate-xss"
    priority  = 30

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }

             text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }

            text_transformation {
              priority = 3
              type     = "COMPRESS_WHITE_SPACE"
            }
          }
          
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "authorization"
              }
            }

            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericmitigatexss", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-rfi-lfi-traversal"
    priority  = 40

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "://"
            
            field_to_match {
              all_query_arguments {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectrfilfitraversal", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-admin-access"
    priority  = 50

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.admin_remote_ipset.arn
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/admin"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectadminaccess", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-php-insecure"
    priority  = 60

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = "php"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = "/"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "_ENV["
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "auto_append_file="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "disable_functions="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "auto_prepend_file="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "safe_mode="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "_SERVER["
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "allow_url_include="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "open_basedir="
            
            field_to_match {
              query_string {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectphpinsecure", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-restrict-sizes"
    priority  = 70

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 4093

            field_to_match {
              single_query_argument {
                name = "cookie"
              }
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }

        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 1024

            field_to_match {
              query_string {}
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }

        statement {
          size_constraint_statement {
            comparison_operator      = "GT"
            size                     = 512

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 5
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericrestrictsizes", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-enforce-csrf"
    priority  = 80

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "post"
            
            field_to_match {
              method {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
        statement{
            size_constraint_statement {
                comparison_operator      = "EQ"
                size                     = 36

                field_to_match {
                  single_query_argument {
                    name = var.rule_csrf_header
                  }
                }

                text_transformation {
                  priority = 5
                  type     = "NONE"
                }
            }
          }
        }
      } 

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericenforcecsrf", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-ssi"
    priority  = 90

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".cfg"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".backup"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".ini"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".conf"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".log"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".bak"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "ENDS_WITH"
            search_string         = ".config"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }

        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/includes"
            
            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority            = 1
              type                = "LOWERCASE"
            }
            text_transformation {
              priority            = 2
              type                = "URL_DECODE"
            }
            text_transformation {
              priority            = 3
              type                = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority            = 4
              type                = "COMPRESS_WHITE_SPACE"
            }
          }
        }
      }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectssi", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }

  #######

  rule {
    name      = "${var.wafv2_prefix}-generic-detect-blacklisted-ips"
    priority  = 100

    action {
      block {}
    }

    statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.admin_remote_ipset.arn
          }
    }

    visibility_config {
        cloudwatch_metrics_enabled  = var.cloudwatch_metrics_enabled
        metric_name                 = replace("${var.wafv2_prefix}genericdetectblacklistedips", "/[^0-9A-Za-z]/", "")
        sampled_requests_enabled    = var.sampled_requests_enabled
    }
  
  }
}


resource aws_wafv2_ip_set admin_remote_ipset {
  name                              = "${var.wafv2_prefix}-generic-match-admin-remote-ip"
  scope                             = "CLOUDFRONT"
  ip_address_version                = "IPV4"
  addresses                         = var.admin_remote_ipset
}

resource aws_wafv2_ip_set blacklisted_ips {
  name = "${var.wafv2_prefix}-generic-match-blacklisted-ips"
  scope                             = "CLOUDFRONT"
  ip_address_version                = "IPV4"
  addresses                         = var.blacklisted_ips
}

resource aws_wafv2_ip_set whitelisted_ips {
  name = "${var.wafv2_prefix}-generic-match-whitelisted-ips"
  scope                             = "CLOUDFRONT"
  ip_address_version                = "IPV4"
  addresses                         = var.whitelisted_ips
}

resource aws_wafv2_ip_set whitelisted_elastic_ips {
  name = "${var.wafv2_prefix}-generic-match-whitelisted_elastic_ips"
  scope                             = "CLOUDFRONT"
  ip_address_version                = "IPV4"
  addresses                         = var.whitelisted_elastic_ips
}