variable "tags" {
  description = "A map of tags to assign to resources"
  type        = map(string)
  default     = {}
}

variable "aws_access_key_id" {
  description = "AWS access key ID"
  type        = string
}

variable "aws_secret_access_key" {
  description = "AWS secret access key"
  type        = string
}

variable "aws_session_token" {
  description = "AWS session token"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "aws_sts_region" {
  description = "The AWS STS region used. The primary site is us-east-1 but is dynamically updated to a different one by Jules if an outage is happening"
  type        = string
  default     = "us-east-1"
}

variable "subnet_names" {
  description = "The names of private subnets"
  type        = list(string)
}

variable "lambda_version" {
  description = "The version of app_shape_servicenow_lambda[]"
  type        = string
  default     = "$LATEST"
}

variable "lambda_name" {
  description = "The name of servicenow certificate renewal detection lambda"
  type        = string
  default     = "shape-servicenow-lambda"
}

variable "lambda_memory_size" {
  description = "The memory size of servicenow certificate renewal lambda"
  type        = string
  default     = "1024"
}

variable "lambda_role_name" {
  description = "The lambda role_name of the lambda"
  type        = string
  default     = ""
}

variable "lambda_time_out" {
  description = "The timeout of certificate renewal detection"
  type        = string
  default     = "900"
}

variable "URL_HTTP_PROXY" {
  description = "Http Proxy url"
  type        = string
}

variable "URL_HTTPS_PROXY" {
  description = "Https Proxy url"
  type        = string
}

variable "AWS_ENV" {
  description = "AWS environment. (dev or uat or prod)"
  type        = string
}

variable "SECRETS_STORE" {
  description = "secrets"
  type        = string
  default     = "/application/app-shape-servicenow-lambda"
}

variable "OTHER_AWS_REGIONS" {
  description = "Other AWS regions"
  type        = list(string)
  default     = []
}


variable "notify_email_id" {
  description = "Notification email ID"
  type        = string
  default     = "joseph.book@chase.com"
}

variable "arn" {
  description = "arn of the lambda"
  type        = string
  default     = ""
}

variable "invoke_arn" {
  description = "arn of to invoke"
  type        = string
  default     = ""
}

variable "vpc_id" {
  description = "The VPC ID where the API Gateway VPC endpoint is deployed"
  type        = string
  default     = ""
}

variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1" # <-- Change this to your region if needed
}

variable "rotation_lambda_account_id" {
  description = "Account ID where the rotation Lambda function exists"
  type        = string
  default     = "945086773129"

}

