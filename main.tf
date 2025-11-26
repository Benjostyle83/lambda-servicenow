###############################
# Local Values                #
###############################
locals {
  environment = "DEV"
  shape_tags = {
    Project     = "Shape"
    Owner       = "ServiceNow"
    Environment = local.environment
  }
  roles = {
    lambda = {
      name              = "app-shape-servicenow-lambda-role"
      assumable_service = ["lambda.amazonaws.com"]
    }
    eventbridge = {
      name              = "app-shape-servicenow-lambda-eventbridge-role"
      assumable_service = ["events.amazonaws.com"]
    }
  }
  endpoints = [
    {
      endpoint              = var.notify_email_id
      filter_policy         = ""
      filter_policy_scope   = null
      raw_message_delivery  = false
      deadletter_queue_name = null
    }
  ]
}



###############################
# KMS for Secrets & SNS       #
###############################
module "app-shape-snow-lambda_kms" {
  source              = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/kms/aws"
  version             = "17.3.0"
  kms_key_alias       = "app-shape-servicenow-lambda-kms"
  kms_key_description = "KMS key for app-shape-servicenow-lambda, Secrets, and SNS"
  use_random_suffix   = true
  tags                = merge(var.tags, local.shape_tags)
}
###############################
# Secrets Manager Module      #
###############################
module "app-shape-snow-lambda_secrets_manager" {
  source              = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/secrets-manager/aws"
  version             = "10.2.0"
  name                = "/application/app-shape-servicenow-lambda"
  secret_kms_key_arn  = module.app-shape-snow-lambda_kms.kms_key_arn
  secret_type         = "keyval"
  secret_content_type = "KEYS"
  rotation = {
    rotation_days = 90
    lambda_arn    = module.app-shape-snow-lambda_rotation_lambda.lambda.arn
  }
  secret_key_list = [
    "servicenow_username",
    "servicenow_password",
    "servicenow_instance_url",
    "api_token",
    "token_url",
    "username",
    "grant_type",
    "client_id",
    "password",

  ]



  tags = merge(var.tags, local.shape_tags)

}
module "app-shape-snow-lambda_rotation_lambda" {
  source        = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/lambda/aws"
  version       = "12.1.0"
  lambda_name   = "app-shape-servicenow-lambda-rotation"
  handler       = "rotation.handler"
  runtime       = "python3.10"
  memory_size   = 128
  timeout       = 120
  iam_role_name = module.app-shape-snow-lambda_roles["lambda"].role_name
  iam_role_arn  = module.app-shape-snow-lambda_roles["lambda"].role_arn
  kms_key_arn   = module.app-shape-snow-lambda_kms.kms_key_arn
  environment_variables = {
    ENVIRONMENT = local.environment
  }
  tags = merge(var.tags, local.shape_tags)
}

###############################
# SNS Email Notification      #
###############################
module "app-shape-snow-lambda_sns_email" {
  source            = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/sns/aws"
  version           = "13.0.0"
  name              = "ap-shape-servicenow-lambda-cert-monitor-email"
  kms_master_key_id = module.app-shape-snow-lambda_kms.kms_key_id
  protocol          = "email"
  email_endpoints   = local.endpoints
  tags              = merge(var.tags, local.shape_tags)
}
###############################
# IAM Roles (for_each)        #
###############################
module "app-shape-snow-lambda_roles" {
  for_each          = local.roles
  source            = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/role/aws"
  version           = "9.2.2"
  name              = each.value.name
  assumable_service = each.value.assumable_service
  tags              = merge(var.tags, local.shape_tags)
}
###############################
# Lambda Function             #
###############################
module "app-shape-servicenow-lambda_lambda" {
  source        = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/lambda/aws"
  version       = "12.1.0"
  lambda_name   = "shape-servicenow-lambda"
  description   = "Validates ServiceNow incidents/changes and creates new incidents if needed, triggered by API Gateway/EventBridge"
  handler       = "servicenow_incident_automation.handler"
  runtime       = "python3.13"
  memory_size   = 256
  timeout       = 300
  iam_role_name = module.app-shape-snow-lambda_roles["lambda"].role_name
  iam_role_arn  = module.app-shape-snow-lambda_roles["lambda"].role_arn
  architectures = ["x86_64"]
  kms_key_arn   = module.app-shape-snow-lambda_kms.kms_key_arn
  environment_variables = {
    SERVICENOW_SECRET_ARN = module.app-shape-snow-lambda_secrets_manager.secret_arn
    SNS_TOPIC_ARN         = module.app-shape-snow-lambda_sns_email.topic_arn
    INCIDENT_ASSIGN_GROUP = "CCB_DGT_SENG_PSE: Technician"
    ENVIRONMENT           = local.environment
    SNOW_SECRET_NAME      = "/application/app-shape-servicenow-lambda"
  }
  tags = merge(var.tags, local.shape_tags)
}
###############################
# IAM Role Policy Updates     #
###############################
module "app-shape-snow-lambda_rpu" {
  source                = "tfe.jpmchase.net/ATLAS-MODULE-REGISTRY/role-policy-updater/aws"
  version               = "60.2.4"
  role_name             = module.app-shape-snow-lambda_roles["lambda"].role_name
  create_managed_policy = true
  secretsmanager_access = {
    read_access   = true
    write_access  = false
    rotate_access = true
    ScopeOfSecretsManagerAccess = [
      module.app-shape-snow-lambda_secrets_manager.secret_arn
    ]
  }
  sns_access = {
    sns_list_topics_access = true
    sns_publish_access     = true
    topic_names            = [module.app-shape-snow-lambda_sns_email.topic_arn]
  }

  kms_access = {
    reader_access = {
      scopeOfKMSAccessList = [
        # module.app-shape-snow-lambda_kms.kms_key_id,
      ]
    }
    writer_access = {
      scopeOfKMSAccessList = [
        #  module.app-shape-snow-lambda_kms.kms_key_id,
      ]
    }
    encryption_access = {
      kmsTargetAccount = var.aws_account_id
      scopeOfKMSAccessList = [
        module.app-shape-snow-lambda_kms.kms_key_id,
        module.app-shape-snow-lambda_kms.kms_key_id
      ]
    }
    decryption_access = {
      kmsTargetAccount = var.aws_account_id
      scopeOfKMSAccessList = [
        module.app-shape-snow-lambda_kms.kms_key_id,
        module.app-shape-snow-lambda_kms.kms_key_id
      ]
    }
    hmac_access = {
      scopeOfKMSAccessList = [
        # module.app-shape-snow-lambda_kms.kms_key_id,
      ]
    }
    signverify_access = {
      scopeOfKMSAccessList = [
        # module.app-shape-snow-lambda_kms.kms_key_id,
      ]
    }
    alias_access = {
      scopeOfKMSAliasList = [
        # module.shape_cert_rotation_kms_email_sns.kms_key_alias_name_without_alias_prefix,
        # module.shape_cert_rotation_kms_s3.kms_key_alias_name_without_alias_prefix
      ]
    }
    account_level_access_tags = {
      read_access     = true
      write_access    = false
      encrypt_access  = false
      decrypt_access  = false
      TagValue        = "Client1"
      resourceTagName = "RPUAccessTag-AccessTag"
    }
    key_rotation_access_alias = {
      read_access       = true
      write_access      = false
      encrypt_access    = false
      decrypt_access    = false
      signverify_access = false
      aliasname = [
        module.app-shape-snow-lambda_kms.kms_key_alias_name_without_alias_prefix,
        module.app-shape-snow-lambda_kms.kms_key_alias_name_without_alias_prefix
      ]
    }
    cross_account_hmac_access = {
      scopeOfKMSAccessList = [
        # module.app-shape-snow-lambda_kms.kms_key_id,
      ]
      kmsTargetAccount = var.aws_account_id
    }
  }

}
