output "billing_contact_id" {
  description = "ID of the billing alternate contact"
  value       = try(aws_account_alternate_contact.billing[0].id, null)
}

output "operations_contact_id" {
  description = "ID of the operations alternate contact"
  value       = try(aws_account_alternate_contact.operations[0].id, null)
}

output "security_contact_id" {
  description = "ID of the security alternate contact"
  value       = try(aws_account_alternate_contact.security[0].id, null)
}
