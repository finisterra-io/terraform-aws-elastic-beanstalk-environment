locals {
  enabled   = module.this.enabled
  partition = join("", data.aws_partition.current[*].partition)
}

data "aws_partition" "current" {
  count = local.enabled ? 1 : 0
}

#
# Service
#
# data "aws_iam_policy_document" "service" {
#   count = local.enabled ? 1 : 0

#   statement {
#     actions = [
#       "sts:AssumeRole"
#     ]

#     principals {
#       type        = "Service"
#       identifiers = ["elasticbeanstalk.amazonaws.com"]
#     }

#     effect = "Allow"
#   }
# }

resource "aws_iam_role" "service" {
  count = local.enabled && var.create_service_role ? 1 : 0

  name               = var.service_iam_role_name
  description        = var.service_iam_role_description
  assume_role_policy = var.service_iam_role_assume_role_policy
  tags               = var.service_iam_role_tags
}

# resource "aws_iam_role_policy_attachment" "enhanced_health" {
#   count = local.enabled && var.enhanced_reporting_enabled ? 1 : 0

#   role       = join("", aws_iam_role.service[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
# }

# resource "aws_iam_role_policy_attachment" "service" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.service[*].name)
#   policy_arn = var.prefer_legacy_service_policy ? "arn:${local.partition}:iam::aws:policy/service-role/AWSElasticBeanstalkService" : "arn:${local.partition}:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"
# }

resource "aws_iam_role_policy_attachment" "service" {
  for_each = local.enabled && var.create_service_role ? toset(var.service_iam_policy_arns) : toset([])


  role       = aws_iam_role.service[0].name
  policy_arn = each.key
}

#
# EC2
#
# data "aws_iam_policy_document" "ec2" {
#   count = local.enabled ? 1 : 0

#   statement {
#     sid = ""

#     actions = [
#       "sts:AssumeRole",
#     ]

#     principals {
#       type        = "Service"
#       identifiers = ["ec2.amazonaws.com"]
#     }

#     effect = "Allow"
#   }

#   statement {
#     sid = ""

#     actions = [
#       "sts:AssumeRole",
#     ]

#     principals {
#       type        = "Service"
#       identifiers = ["ssm.amazonaws.com"]
#     }

#     effect = "Allow"
#   }
# }

# resource "aws_iam_role_policy_attachment" "elastic_beanstalk_multi_container_docker" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker"
# }

resource "aws_iam_role" "ec2" {
  count = local.enabled && var.create_ec2_role ? 1 : 0

  name               = var.ec2_iam_role_name
  description        = var.ec2_iam_role_description
  assume_role_policy = var.ec2_iam_role_assume_role_policy
  tags               = var.ec2_iam_role_tags
}

resource "aws_iam_role_policy_attachment" "role" {
  for_each = local.enabled && var.create_ec2_role ? toset(var.ec2_iam_policy_arns) : toset([])


  role       = aws_iam_role.ec2[0].name
  policy_arn = each.key
}

resource "aws_iam_instance_profile" "ec2" {
  count = local.enabled ? 1 : 0

  name = "${module.this.id}-eb-ec2"
  role = join("", aws_iam_role.ec2[*].name)
  tags = module.this.tags
}

# resource "aws_iam_role_policy" "default" {
#   count = local.enabled ? 1 : 0

#   name   = "${module.this.id}-eb-default"
#   role   = join("", aws_iam_role.ec2[*].id)
#   policy = join("", data.aws_iam_policy_document.extended[*].json)
# }

# resource "aws_iam_role_policy_attachment" "web_tier" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/AWSElasticBeanstalkWebTier"
# }

# resource "aws_iam_role_policy_attachment" "worker_tier" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/AWSElasticBeanstalkWorkerTier"
# }

# resource "aws_iam_role_policy_attachment" "ssm_ec2" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = var.prefer_legacy_ssm_policy ? "arn:${local.partition}:iam::aws:policy/service-role/AmazonEC2RoleforSSM" : "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"

#   lifecycle {
#     create_before_destroy = true
#   }
# }

# resource "aws_iam_role_policy_attachment" "ssm_automation" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonSSMAutomationRole"

#   lifecycle {
#     create_before_destroy = true
#   }
# }

# # http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker.container.console.html
# # http://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr_managed_policies.html#AmazonEC2ContainerRegistryReadOnly
# resource "aws_iam_role_policy_attachment" "ecr_readonly" {
#   count = local.enabled ? 1 : 0

#   role       = join("", aws_iam_role.ec2[*].name)
#   policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
# }

# resource "aws_ssm_activation" "ec2" {
#   count = local.enabled ? 1 : 0

#   name               = module.this.id
#   iam_role           = join("", aws_iam_role.ec2[*].id)
#   registration_limit = var.autoscale_max
#   tags               = module.this.tags
#   depends_on         = [aws_elastic_beanstalk_environment.default]
# }

# data "aws_iam_policy_document" "default" {
#   count = local.enabled ? 1 : 0

#   statement {
#     actions = [
#       "elasticloadbalancing:DescribeInstanceHealth",
#       "elasticloadbalancing:DescribeLoadBalancers",
#       "elasticloadbalancing:DescribeTargetHealth",
#       "ec2:DescribeInstances",
#       "ec2:DescribeInstanceStatus",
#       "ec2:GetConsoleOutput",
#       "ec2:AssociateAddress",
#       "ec2:DescribeAddresses",
#       "ec2:DescribeSecurityGroups",
#       "sqs:GetQueueAttributes",
#       "sqs:GetQueueUrl",
#       "autoscaling:DescribeAutoScalingGroups",
#       "autoscaling:DescribeAutoScalingInstances",
#       "autoscaling:DescribeScalingActivities",
#       "autoscaling:DescribeNotificationConfigurations",
#     ]

#     resources = ["*"]

#     effect = "Allow"
#   }

#   statement {
#     sid = "AllowOperations"

#     actions = [
#       "autoscaling:AttachInstances",
#       "autoscaling:CreateAutoScalingGroup",
#       "autoscaling:CreateLaunchConfiguration",
#       "autoscaling:DeleteLaunchConfiguration",
#       "autoscaling:DeleteAutoScalingGroup",
#       "autoscaling:DeleteScheduledAction",
#       "autoscaling:DescribeAccountLimits",
#       "autoscaling:DescribeAutoScalingGroups",
#       "autoscaling:DescribeAutoScalingInstances",
#       "autoscaling:DescribeLaunchConfigurations",
#       "autoscaling:DescribeLoadBalancers",
#       "autoscaling:DescribeNotificationConfigurations",
#       "autoscaling:DescribeScalingActivities",
#       "autoscaling:DescribeScheduledActions",
#       "autoscaling:DetachInstances",
#       "autoscaling:PutScheduledUpdateGroupAction",
#       "autoscaling:ResumeProcesses",
#       "autoscaling:SetDesiredCapacity",
#       "autoscaling:SetInstanceProtection",
#       "autoscaling:SuspendProcesses",
#       "autoscaling:TerminateInstanceInAutoScalingGroup",
#       "autoscaling:UpdateAutoScalingGroup",
#       "cloudwatch:PutMetricAlarm",
#       "ec2:AssociateAddress",
#       "ec2:AllocateAddress",
#       "ec2:AuthorizeSecurityGroupEgress",
#       "ec2:AuthorizeSecurityGroupIngress",
#       "ec2:CreateSecurityGroup",
#       "ec2:DeleteSecurityGroup",
#       "ec2:DescribeAccountAttributes",
#       "ec2:DescribeAddresses",
#       "ec2:DescribeImages",
#       "ec2:DescribeInstances",
#       "ec2:DescribeKeyPairs",
#       "ec2:DescribeSecurityGroups",
#       "ec2:DescribeSnapshots",
#       "ec2:DescribeSubnets",
#       "ec2:DescribeVpcs",
#       "ec2:DisassociateAddress",
#       "ec2:ReleaseAddress",
#       "ec2:RevokeSecurityGroupEgress",
#       "ec2:RevokeSecurityGroupIngress",
#       "ec2:TerminateInstances",
#       "ecs:CreateCluster",
#       "ecs:DeleteCluster",
#       "ecs:DescribeClusters",
#       "ecs:RegisterTaskDefinition",
#       "elasticbeanstalk:*",
#       "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
#       "elasticloadbalancing:ConfigureHealthCheck",
#       "elasticloadbalancing:CreateLoadBalancer",
#       "elasticloadbalancing:DeleteLoadBalancer",
#       "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
#       "elasticloadbalancing:DescribeInstanceHealth",
#       "elasticloadbalancing:DescribeLoadBalancers",
#       "elasticloadbalancing:DescribeTargetHealth",
#       "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
#       "elasticloadbalancing:DescribeTargetGroups",
#       "elasticloadbalancing:RegisterTargets",
#       "elasticloadbalancing:DeregisterTargets",
#       "iam:ListRoles",
#       "logs:CreateLogGroup",
#       "logs:PutRetentionPolicy",
#       "rds:DescribeDBEngineVersions",
#       "rds:DescribeDBInstances",
#       "rds:DescribeOrderableDBInstanceOptions",
#       "s3:GetObject",
#       "s3:GetObjectAcl",
#       "s3:ListBucket",
#       "sns:CreateTopic",
#       "sns:GetTopicAttributes",
#       "sns:ListSubscriptionsByTopic",
#       "sns:Subscribe",
#       "sqs:GetQueueAttributes",
#       "sqs:GetQueueUrl",
#       "codebuild:CreateProject",
#       "codebuild:DeleteProject",
#       "codebuild:BatchGetBuilds",
#       "codebuild:StartBuild",
#     ]

#     resources = ["*"]

#     effect = "Allow"
#   }

#   statement {
#     sid = "AllowPassRole"

#     actions = [
#       "iam:PassRole"
#     ]

#     resources = [
#       join("", aws_iam_role.ec2[*].arn),
#       join("", aws_iam_role.service[*].arn)
#     ]

#     effect = "Allow"
#   }

#   statement {
#     sid = "AllowS3OperationsOnElasticBeanstalkBuckets"

#     actions = [
#       "s3:*"
#     ]

#     resources = [
#       #bridgecrew:skip=BC_AWS_IAM_57:Skipping "Ensure IAM policies does not allow write access without constraint"
#       #bridgecrew:skip=BC_AWS_IAM_56:Skipping "Ensure IAM policies do not allow permissions management / resource exposure without constraint"
#       #bridgecrew:skip=BC_AWS_IAM_55:Skipping "Ensure IAM policies do not allow data exfiltration"
#       "arn:${local.partition}:s3:::*"
#     ]

#     effect = "Allow"
#   }

#   statement {
#     sid = "AllowDeleteCloudwatchLogGroups"

#     actions = [
#       "logs:DeleteLogGroup"
#     ]

#     resources = [
#       "arn:${local.partition}:logs:*:*:log-group:/aws/elasticbeanstalk*"
#     ]

#     effect = "Allow"
#   }

#   statement {
#     sid = "AllowCloudformationOperationsOnElasticBeanstalkStacks"

#     actions = [
#       "cloudformation:*"
#     ]

#     resources = [
#       "arn:${local.partition}:cloudformation:*:*:stack/awseb-*",
#       "arn:${local.partition}:cloudformation:*:*:stack/eb-*"
#     ]

#     effect = "Allow"
#   }
# }

# data "aws_iam_policy_document" "extended" {
#   count                     = local.enabled ? 1 : 0
#   source_policy_documents   = [join("", data.aws_iam_policy_document.default[*].json)]
#   override_policy_documents = [var.extended_ec2_policy_document]
# }



locals {
  # Remove `Name` tag from the map of tags because Elastic Beanstalk generates the `Name` tag automatically
  # and if it is provided, terraform tries to recreate the application on each `plan/apply`
  # `Namespace` should be removed as well since any string that contains `Name` forces recreation
  # https://github.com/terraform-providers/terraform-provider-aws/issues/3963
  tags = { for t in keys(module.this.tags) : t => module.this.tags[t] if t != "Name" && t != "Namespace" }

  classic_elb_settings = [
    {
      namespace = "aws:elb:loadbalancer"
      name      = "CrossZone"
      value     = var.loadbalancer_crosszone
    },
    {
      namespace = "aws:elb:loadbalancer"
      name      = "SecurityGroups"
      value     = join(",", sort(var.loadbalancer_security_groups))
    },
    {
      namespace = "aws:elb:loadbalancer"
      name      = "ManagedSecurityGroup"
      value     = var.loadbalancer_managed_security_group
    },

    {
      namespace = "aws:elb:listener"
      name      = "ListenerProtocol"
      value     = "HTTP"
    },
    {
      namespace = "aws:elb:listener"
      name      = "InstancePort"
      value     = var.application_port
    },
    {
      namespace = "aws:elb:listener"
      name      = "ListenerEnabled"
      value     = var.http_listener_enabled || var.loadbalancer_certificate_arn == "" ? "true" : "false"
    },
    {
      namespace = "aws:elb:listener:443"
      name      = "ListenerProtocol"
      value     = "HTTPS"
    },
    {
      namespace = "aws:elb:listener:443"
      name      = "InstancePort"
      value     = var.application_port
    },
    {
      namespace = "aws:elb:listener:443"
      name      = "SSLCertificateId"
      value     = var.loadbalancer_certificate_arn
    },
    {
      namespace = "aws:elb:listener:443"
      name      = "ListenerEnabled"
      value     = var.loadbalancer_certificate_arn == "" ? "false" : "true"
    },
    {
      namespace = "aws:elb:listener:${var.ssh_listener_port}"
      name      = "ListenerProtocol"
      value     = "TCP"
    },
    {
      namespace = "aws:elb:listener:${var.ssh_listener_port}"
      name      = "InstancePort"
      value     = "22"
    },
    {
      namespace = "aws:elb:listener:${var.ssh_listener_port}"
      name      = "ListenerEnabled"
      value     = var.ssh_listener_enabled
    },
    {
      namespace = "aws:elb:policies"
      name      = "ConnectionSettingIdleTimeout"
      value     = var.loadbalancer_connection_idle_timeout
    },
    {
      namespace = "aws:elb:policies"
      name      = "ConnectionDrainingEnabled"
      value     = "true"
    },
  ]

  generic_alb_settings = [
    {
      namespace = "aws:elbv2:loadbalancer"
      name      = "SecurityGroups"
      value     = join(",", sort(var.loadbalancer_security_groups))
    }
  ]

  shared_alb_settings = [
    {
      namespace = "aws:elasticbeanstalk:environment"
      name      = "LoadBalancerIsShared"
      value     = "true"
    },
    {
      namespace = "aws:elbv2:loadbalancer"
      name      = "SharedLoadBalancer"
      value     = var.shared_loadbalancer_arn
    }
  ]

  alb_settings = [
    {
      namespace = "aws:elbv2:listener:default"
      name      = "ListenerEnabled"
      value     = var.http_listener_enabled || var.loadbalancer_certificate_arn == "" ? "true" : "false"
    },
    {
      namespace = "aws:elbv2:loadbalancer"
      name      = "ManagedSecurityGroup"
      value     = var.loadbalancer_managed_security_group
    },
    {
      namespace = "aws:elbv2:listener:443"
      name      = "ListenerEnabled"
      value     = var.loadbalancer_certificate_arn == "" ? "false" : "true"
    },
    {
      namespace = "aws:elbv2:listener:443"
      name      = "Protocol"
      value     = "HTTPS"
    },
    {
      namespace = "aws:elbv2:listener:443"
      name      = "SSLCertificateArns"
      value     = var.loadbalancer_certificate_arn
    },
    {
      namespace = "aws:elbv2:listener:443"
      name      = "SSLPolicy"
      value     = var.loadbalancer_type == "application" ? var.loadbalancer_ssl_policy : ""
    },
    ###===================== Application Load Balancer Health check settings =====================================================###
    # The Application Load Balancer health check does not take into account the Elastic Beanstalk health check path
    # http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-applicationloadbalancer.html
    # http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environments-cfg-applicationloadbalancer.html#alb-default-process.config
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "HealthCheckPath"
      value     = var.healthcheck_url
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "MatcherHTTPCode"
      value     = join(",", sort(var.healthcheck_httpcodes_to_match))
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "HealthCheckTimeout"
      value     = var.healthcheck_timeout
    }
  ]

  alb_settings_logging = !var.loadbalancer_is_shared && var.enable_loadbalancer_logs ? [
    {
      namespace = "aws:elbv2:loadbalancer"
      name      = "AccessLogsS3Enabled"
      value     = "true"
    },
    {
      namespace = "aws:elbv2:loadbalancer"
      name      = "AccessLogsS3Bucket"
      value     = module.elb_logs.bucket_id
  }] : []

  nlb_settings = [
    {
      namespace = "aws:elbv2:listener:default"
      name      = "ListenerEnabled"
      value     = var.http_listener_enabled
    }
  ]

  # Settings for all loadbalancer types (including shared ALB)
  generic_elb_settings = [
    {
      namespace = "aws:elasticbeanstalk:environment"
      name      = "LoadBalancerType"
      value     = var.loadbalancer_type
    }
  ]

  # Settings for beanstalk managed elb only (so not for shared ALB)
  beanstalk_elb_settings = [
    {
      namespace = "aws:ec2:vpc"
      name      = "ELBSubnets"
      value     = join(",", sort(var.loadbalancer_subnets))
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "Port"
      value     = var.application_port
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "Protocol"
      value     = var.loadbalancer_type == "network" ? "TCP" : "HTTP"
    },
    {
      namespace = "aws:ec2:vpc"
      name      = "ELBScheme"
      value     = var.environment_type == "LoadBalanced" ? var.elb_scheme : ""
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "HealthCheckInterval"
      value     = var.healthcheck_interval
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "HealthyThresholdCount"
      value     = var.healthcheck_healthy_threshold_count
    },
    {
      namespace = "aws:elasticbeanstalk:environment:process:default"
      name      = "UnhealthyThresholdCount"
      value     = var.healthcheck_unhealthy_threshold_count
    }
  ]

  # Select elb configuration depending on loadbalancer_type
  elb_settings_nlb        = var.loadbalancer_type == "network" ? concat(local.nlb_settings, local.generic_elb_settings, local.beanstalk_elb_settings) : []
  elb_settings_alb        = var.loadbalancer_type == "application" && !var.loadbalancer_is_shared ? concat(local.alb_settings, local.generic_alb_settings, local.generic_elb_settings, local.beanstalk_elb_settings, local.alb_settings_logging) : []
  elb_settings_shared_alb = var.loadbalancer_type == "application" && var.loadbalancer_is_shared ? concat(local.shared_alb_settings, local.generic_alb_settings, local.generic_elb_settings) : []
  elb_setting_classic     = var.loadbalancer_type == "classic" ? concat(local.classic_elb_settings, local.generic_elb_settings, local.beanstalk_elb_settings) : []

  # If the tier is "WebServer" add the elb_settings, otherwise exclude them
  elb_settings_final = var.tier == "WebServer" ? concat(local.elb_settings_nlb, local.elb_settings_alb, local.elb_settings_shared_alb, local.elb_setting_classic) : []
}

#
# Full list of options:
# http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html#command-options-general-elasticbeanstalkmanagedactionsplatformupdate
#
resource "aws_elastic_beanstalk_environment" "default" {
  count = local.enabled ? 1 : 0

  name                   = module.this.id
  application            = var.elastic_beanstalk_application_name
  description            = var.description
  tier                   = var.tier
  solution_stack_name    = var.solution_stack_name
  wait_for_ready_timeout = var.wait_for_ready_timeout
  version_label          = var.version_label
  tags                   = local.tags

  dynamic "setting" {
    for_each = var.settings
    content {
      name      = setting.value["name"]
      namespace = setting.value["namespace"]
      resource  = ""
      value     = setting.value["value"]
    }
  }
}

resource "random_string" "elb_logs_suffix" {
  length  = 5
  special = false
  upper   = false
}

module "elb_logs" {
  source             = "cloudposse/lb-s3-bucket/aws"
  version            = "0.19.0"
  enabled            = var.enable_loadbalancer_logs && local.enabled && var.tier == "WebServer" && var.environment_type == "LoadBalanced" && var.loadbalancer_type != "network" && !var.loadbalancer_is_shared ? true : false
  name               = "${module.this.id}-alb-logs-${random_string.elb_logs_suffix.result}"
  force_destroy      = var.force_destroy
  versioning_enabled = var.s3_bucket_versioning_enabled
  context            = module.this.context
}

module "dns_hostname" {
  source  = "cloudposse/route53-cluster-hostname/aws"
  version = "0.12.2"

  enabled = local.enabled && var.dns_zone_id != "" && var.tier == "WebServer" ? true : false

  dns_name = var.dns_subdomain != "" ? var.dns_subdomain : module.this.name
  zone_id  = var.dns_zone_id
  records  = [join("", aws_elastic_beanstalk_environment.default[*].cname)]

  context = module.this.context
}

data "aws_lb_listener" "http" {
  count             = local.enabled && var.loadbalancer_redirect_http_to_https ? 1 : 0
  load_balancer_arn = var.loadbalancer_is_shared ? var.shared_loadbalancer_arn : one(aws_elastic_beanstalk_environment.default[0].load_balancers)
  port              = var.application_port
}

resource "aws_lb_listener_rule" "redirect_http_to_https" {
  count        = local.enabled && var.loadbalancer_redirect_http_to_https ? 1 : 0
  listener_arn = one(data.aws_lb_listener.http[*].arn)
  priority     = var.loadbalancer_redirect_http_to_https_priority

  condition {
    path_pattern {
      values = var.loadbalancer_redirect_http_to_https_path_pattern
    }
  }

  action {
    type = "redirect"
    redirect {
      host        = var.loadbalancer_redirect_http_to_https_host
      port        = var.loadbalancer_redirect_http_to_https_port
      protocol    = "HTTPS"
      status_code = var.loadbalancer_redirect_http_to_https_status_code
    }
  }
}
