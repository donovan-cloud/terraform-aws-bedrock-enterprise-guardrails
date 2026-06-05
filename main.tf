# AWS Bedrock Enterprise Guardrails Infrastructure Architecture

# 1. Automated Encryption Key for GenAI Telemetry Data
resource "aws_kms_key" "bedrock_security_key" {
  description             = "KMS Key for Bedrock Audit Logs and Model Invocations"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# 2. Immutable S3 Data Vault for LLM Input/Output Tracking
resource "aws_s3_bucket" "bedrock_audit_vault" {
  bucket        = "enterprise-bedrock-invocation-audit-vault-prod"
  force_destroy = false
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

# 3. Enterprise Bedrock Guardrail Deployment
resource "aws_bedrock_guardrail" "enterprise_guardrail" {
  name        = "corporate-compliance-guardrail-prod"
  description = "Enforces PII masking and blocks prompt injection variants for production models"

  # Block Toxicity and Malicious Content
  content_filter_config {
    filters {
      type       = "PROMPT_ATTACK" # Prevents prompt injection, jailbreaking, and system override attempts
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters {
      type       = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters {
      type       = "VIOLENCE"
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

# 4. Centralized Inference Model Invocation Logging
resource "aws_bedrock_model_invocation_logging_configuration" "audit_logging" {
  dependent_on = [aws_s3_bucket_public_access_block.block_vault_public_access]

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
