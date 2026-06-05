# AWS Bedrock Enterprise Guardrails Infrastructure Architecture

# Data sources required for dynamic account tracking
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# 1. Automated Encryption Key for GenAI Telemetry Data
resource "aws_kms_key" "bedrock_security_key" {
  description             = "KMS Key for Bedrock Audit Logs and Model Invocations"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# 2. Immutable S3 Data Vault for LLM Input/Output Tracking
resource "aws_s3_bucket" "bedrock_audit_vault" {
  bucket              = "enterprise-bedrock-invocation-audit-vault-prod"
  force_destroy       = false
  object_lock_enabled = true # Aligns code with WORM capabilities in README
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_encryption" {
  bucket = aws_s3_bucket.bedrock_audit_vault.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bedrock_security_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block_vault_public_access" {
  bucket                  = aws_s3_bucket.bedrock_audit_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. Mandatory S3 Bucket Policy allowing Amazon Bedrock to write telemetry logs
resource "aws_s3_bucket_policy" "allow_bedrock_logging" {
  bucket = aws_s3_bucket.bedrock_audit_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBedrockToPutLogs"
        Effect = "Allow"
        Principal = {
          Service = "://amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.bedrock_audit_vault.arn}/bedrock-invocation-telemetry/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowBedrockToGetBucketLocation"
        Effect = "Allow"
        Principal = {
          Service = "://amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.bedrock_audit_vault.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# 4. Enterprise Bedrock Guardrail Deployment
resource "aws_bedrock_guardrail" "enterprise_guardrail" {
  name        = "corporate-compliance-guardrail-prod"
  description = "Enforces PII masking and blocks prompt injection variants for production models"

  # Block Toxicity and Malicious Content
  content_filter_config {
    filters {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters {
      type            = "VIOLENCE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  # Mask Sensitive Corporate and Personal Data
  pii_entity_config {
    entities {
      type   = "US_SOCIAL_SECURITY_NUMBER"
      action = "ANONYMIZE"
    }
    entities {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }
    entities {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "ANONYMIZE"
    }
  }

  # Block Regulated or Unauthorized Corporate Words
  sensitive_information_policy_config {
    words_config {
      text = "unreleased_product_code_x"
    }
    words_config {
      text = "internal_master_password"
    }
  }

  blocked_input_messaging  = "The request was blocked by corporate security guardrails due to compliance violations."
  blocked_output_messaging = "Model output was intercepted due to sensitive corporate data leak identification."
}

# 5. Centralized Inference Model Invocation Logging Configuration
resource "aws_bedrock_model_invocation_logging_configuration" "audit_logging" {
  # Fixed critical syntax typo from dependent_on to depends_on
  # Added the bucket policy requirement as an explicit dependency
  depends_on = [
    aws_s3_bucket_public_access_block.block_vault_public_access,
    aws_s3_bucket_policy.allow_bedrock_logging
  ]

  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    s3_config {
      bucket_name = aws_s3_bucket.bedrock_audit_vault.bucket
      key_prefix  = "bedrock-invocation-telemetry/"
    }
  }
}
