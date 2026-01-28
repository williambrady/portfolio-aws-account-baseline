terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Billing Contact
resource "aws_account_alternate_contact" "billing" {
  count = var.enable_alternate_contacts ? 1 : 0

  alternate_contact_type = "BILLING"
  name                   = var.billing_contact.name
  title                  = var.billing_contact.title
  email_address          = var.billing_contact.email
  phone_number           = var.billing_contact.phone
}

# Operations Contact
resource "aws_account_alternate_contact" "operations" {
  count = var.enable_alternate_contacts ? 1 : 0

  alternate_contact_type = "OPERATIONS"
  name                   = var.operations_contact.name
  title                  = var.operations_contact.title
  email_address          = var.operations_contact.email
  phone_number           = var.operations_contact.phone
}

# Security Contact
resource "aws_account_alternate_contact" "security" {
  count = var.enable_alternate_contacts ? 1 : 0

  alternate_contact_type = "SECURITY"
  name                   = var.security_contact.name
  title                  = var.security_contact.title
  email_address          = var.security_contact.email
  phone_number           = var.security_contact.phone
}
