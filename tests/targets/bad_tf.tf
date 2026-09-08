# Deliberately misconfigured Terraform
resource "aws_s3_bucket" "public" {
  bucket = "example-public"
  acl    = "public-read"
}

resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "db" {
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  storage_encrypted    = false
}
