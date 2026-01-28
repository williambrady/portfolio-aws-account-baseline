output "minimum_password_length" {
  description = "Minimum length for IAM user passwords"
  value       = aws_iam_account_password_policy.strict.minimum_password_length
}

output "max_password_age" {
  description = "Password expiration period in days"
  value       = aws_iam_account_password_policy.strict.max_password_age
}

output "password_reuse_prevention" {
  description = "Number of previous passwords that cannot be reused"
  value       = aws_iam_account_password_policy.strict.password_reuse_prevention
}

output "hard_expiry" {
  description = "Whether password expiration requires admin reset"
  value       = aws_iam_account_password_policy.strict.hard_expiry
}

output "allow_users_to_change_password" {
  description = "Whether users can change their own passwords"
  value       = aws_iam_account_password_policy.strict.allow_users_to_change_password
}
