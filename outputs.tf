output "guardrail_id" {
  value       = aws_bedrock_guardrail.enterprise_guardrail.id
  description = "The unique identifier of the deployed Bedrock Guardrail"
}

output "audit_vault_arn" {
  value       = aws_s3_bucket.bedrock_audit_vault.arn
  description = "The Amazon Resource Name of the secure encryption audit vault"
}
