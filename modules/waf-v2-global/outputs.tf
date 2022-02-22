output web_acl_id {
  description = "AWS wafv2 web acl id."
  value       = aws_wafv2_web_acl.waf_v2_acl.id
}

output web_acl_name {
  description = "The name or description of the web ACL."
  value       = aws_wafv2_web_acl.waf_v2_acl.name
}
