terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Default provider (us-east-1)
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = var.tags
  }
}

# Regional provider aliases
provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "us-east-2"
  region = "us-east-2"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "us-west-1"
  region = "us-west-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "eu-west-1"
  region = "eu-west-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "eu-west-2"
  region = "eu-west-2"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "eu-west-3"
  region = "eu-west-3"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "eu-north-1"
  region = "eu-north-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-southeast-1"
  region = "ap-southeast-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-southeast-2"
  region = "ap-southeast-2"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-northeast-1"
  region = "ap-northeast-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-northeast-2"
  region = "ap-northeast-2"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-northeast-3"
  region = "ap-northeast-3"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ap-south-1"
  region = "ap-south-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "ca-central-1"
  region = "ca-central-1"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "sa-east-1"
  region = "sa-east-1"

  default_tags {
    tags = var.tags
  }
}
