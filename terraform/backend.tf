terraform {
  backend "s3" {
    # These values are provided via -backend-config flags during init
    # bucket = "secops-tfstate-ACCOUNT_ID"
    # key    = "baseline/terraform.tfstate"
    # region = "us-east-1"
  }
}
