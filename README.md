# AWS Bedrock Enterprise Security & Governance Guardrails

[![Architecture](https://img.shields.io/badge/Architecture-GenAI%20Security-blueviolet.svg)](https://aws.amazon.com/bedrock/)
[![Framework](https://img.shields.io/badge/Compliance-OWASP%20Top%2010%20LLM-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![IaC](https://img.shields.io/badge/IaC-Terraform-blue.svg)](https://www.terraform.io/)

## 📋 Operational Overview

This repository contains an enterprise-grade Terraform framework engineered to deploy, govern, and secure **AWS Bedrock** model invocation layers. 

Deploying foundational models within FinTech and regulated environments introduces severe risks, including prompt injection, sensitive data leakage (PII/PCI), and toxic output generation. This architecture establishes native automated infrastructure boundaries around Bedrock, configuring custom data-masking guardrails, enforcing synchronous invocation logging to an immutable WORM S3 bucket, and implementing a least-privilege IAM control surface to block un-audited model access.

---

### 🛡️ Core GenAI Security Controls Deployed

* **Bedrock Guardrails Token Filtering:** Configures automated content filters, PII data-masking mechanisms (SSNs, API Keys, Passwords), and blocked phrase lexicons directly at the model input/output plane.
* **Immutable Invocation Auditing Vault:** Deploys a centralized CloudWatch Logs stream backed by a dual-encrypted, object-locked S3 bucket to capture 100% of model prompts, responses, and token metadata.
* **Network & Identity Isolation:** Limits model execution endpoints to internal VPC perimeters and attaches rigid customer-managed IAM policies to reject unauthenticated inference workflows.

---

## 📂 Repository Structural Mapping

```text
terraform-aws-bedrock-enterprise-guardrails/
├── README.md                      # Architecture and compliance overview
├── main.tf                        # Core Bedrock Guardrail and security infrastructure
├── variables.tf                   # Environment input configuration variables
└── outputs.tf                     # Structural resource outputs for integration
