# module "aws_security_group" {
#   source  = "cloudposse/security-group/aws"
#   version = "1.0.1"

#   enabled = local.enabled && var.create_security_group

#   security_group_name        = length(var.security_group_name) > 0 ? var.security_group_name : [module.this.id]
#   security_group_description = var.security_group_description

#   allow_all_egress = var.allow_all_egress

#   rules = var.additional_security_group_rules

#   vpc_id = var.vpc_id

#   create_before_destroy         = var.security_group_create_before_destroy
#   security_group_create_timeout = var.security_group_create_timeout
#   security_group_delete_timeout = var.security_group_delete_timeout

#   context = module.this.context
# }


resource "aws_security_group" "default" {
  count       = module.this.enabled && var.create_security_group ? 1 : 0
  name        = var.security_group_name
  description = var.security_group_description
  vpc_id      = var.vpc_id
  tags        = var.security_group_tags
}

resource "aws_security_group_rule" "default" {
  for_each = var.create_security_group ? var.security_group_rules : {}

  type              = each.value.type
  description       = try(each.value.description, "")
  from_port         = try(each.value.from_port, -1)
  to_port           = try(each.value.to_port, -1)
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  security_group_id = each.value.security_group_id
}
