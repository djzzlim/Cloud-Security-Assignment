#no waf ok

#ok
# Configure Docker provider
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Domain name for SSL certificate (optional)"
  type        = string
  default     = ""
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "my-app"
}

variable "db_password" {
  description = "Database password"
  type        = string
  default     = "myapp123"
  sensitive   = true
}

variable "s3_bucket_name" {
  description = "S3 bucket name to create"
  type        = string
  default     = "my-app-bucket-kjshjh"
}

variable "create_admin_user" {
  description = "Whether to create an admin IAM user with full access"
  type        = bool
  default     = true
}

variable "create_iam_user" {
  description = "Whether to create an IAM user for console and programmatic access"
  type        = bool
  default     = true
}

provider "aws" {
  region = var.aws_region
}

# Configure Docker provider with ECR authentication
provider "docker" {
  registry_auth {
    address  = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
    username = "AWS"
    password = data.aws_ecr_authorization_token.token.password
  }
}

# Get ECR authorization token
data "aws_ecr_authorization_token" "token" {
  registry_id = data.aws_caller_identity.current.account_id
}

# Data sources (ONLY ONE INSTANCE)
data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.app_name}-vpc"
    Environment = var.environment
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw"
  }
}

# Subnets
resource "aws_subnet" "public_web_az1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-web-az1"
  }
}

resource "aws_subnet" "public_web_az2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-web-az2"
  }
}

resource "aws_subnet" "private_db_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "private-db-az1"
  }
}

resource "aws_subnet" "private_db_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "private-db-az2"
  }
}

# Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "private-route-table"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public_web_az1_assoc" {
  subnet_id      = aws_subnet.public_web_az1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_web_az2_assoc" {
  subnet_id      = aws_subnet.public_web_az2.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_db_az1_assoc" {
  subnet_id      = aws_subnet.private_db_az1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_db_az2_assoc" {
  subnet_id      = aws_subnet.private_db_az2.id
  route_table_id = aws_route_table.private_rt.id
}

# Security Groups

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoint_sg" {
  name        = "vpc-endpoint-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "vpc-endpoint-security-group"
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "alb-security-group"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "alb-security-group"
  }
}

# Simplified ECS Fargate security group
resource "aws_security_group" "ecs_fargate_sg" {
  name        = "ecs-fargate-security-group"
  description = "Security group for ECS Fargate tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Flask app from ALB"
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ecs-fargate-security-group"
  }
}

# Security Group for DB Admin Instance
resource "aws_security_group" "db_admin_sg" {
  name        = "db-admin-security-group"
  description = "Security group for database admin instance (SSM access only)"
  vpc_id      = aws_vpc.main.id

  # No inbound SSH - only SSM access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-admin-security-group"
  }
}

# RDS Security Group - accessible from ECS Fargate and DB Admin instance
resource "aws_security_group" "rds_sg" {
  name        = "rds-security-group"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from ECS Fargate"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_fargate_sg.id]
  }

  ingress {
    description     = "MySQL from database admin instance"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.db_admin_sg.id]
  }

  tags = {
    Name = "rds-security-group"
  }
}

# IAM Role for DB Admin Instance
resource "aws_iam_role" "db_admin_role" {
  name = "db-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "db-admin-role"
  }
}

# Attach SSM policy to DB admin role
resource "aws_iam_role_policy_attachment" "db_admin_ssm_policy" {
  role       = aws_iam_role.db_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance profile for DB admin instance
resource "aws_iam_instance_profile" "db_admin_profile" {
  name = "db-admin-profile"
  role = aws_iam_role.db_admin_role.name
}

# Database management instance (accessed via SSM Session Manager only)
resource "aws_instance" "db_admin" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.db_admin_sg.id]
  subnet_id              = aws_subnet.public_web_az1.id
  iam_instance_profile   = aws_iam_instance_profile.db_admin_profile.name

  # Enable public IP for package installation
  associate_public_ip_address = true

  tags = {
    Name        = "db-admin-instance"
    Environment = var.environment
    Purpose     = "RDS-access-via-SSM"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# IAM Roles for ECS Fargate
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task_role" {
  name = "ecsTaskRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Add ECS Exec permissions to task role
resource "aws_iam_role_policy_attachment" "ecs_task_ssm_policy" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# S3 Bucket for application storage (PUBLIC ACCESS)
resource "aws_s3_bucket" "app_bucket" {
  bucket = var.s3_bucket_name
  
  # Add this line to force delete bucket with all objects
  force_destroy = true

  tags = {
    Name = "my-app-bucket"
  }

  lifecycle {
    prevent_destroy = false
  }
}

# Configure bucket ownership to allow ACLs
resource "aws_s3_bucket_ownership_controls" "app_bucket_ownership" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Enable public access block settings (DISABLE restrictions for public access)
resource "aws_s3_bucket_public_access_block" "app_bucket_pab" {
  bucket = aws_s3_bucket.app_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false

  depends_on = [aws_s3_bucket_ownership_controls.app_bucket_ownership]
}

# Set bucket ACL to allow public read
resource "aws_s3_bucket_acl" "app_bucket_acl" {
  bucket = aws_s3_bucket.app_bucket.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.app_bucket_ownership,
    aws_s3_bucket_public_access_block.app_bucket_pab,
  ]
}

# Bucket versioning
resource "aws_s3_bucket_versioning" "app_bucket_versioning" {
  bucket = aws_s3_bucket.app_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Bucket policy for public read access (backup to ACLs)
resource "aws_s3_bucket_policy" "app_bucket_policy" {
  bucket = aws_s3_bucket.app_bucket.id
  
  depends_on = [aws_s3_bucket_public_access_block.app_bucket_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.app_bucket.arn}/*"
      }
    ]
  })
}

# CORS configuration for web access
resource "aws_s3_bucket_cors_configuration" "app_bucket_cors" {
  bucket = aws_s3_bucket.app_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# Website configuration (optional - for static website hosting)
resource "aws_s3_bucket_website_configuration" "app_bucket_website" {
  bucket = aws_s3_bucket.app_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# IAM policy for S3 access
resource "aws_iam_role_policy" "ecs_s3_policy" {
  name = "ecs-s3-access"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      }
    ]
  })
}

# ECR Repository
resource "aws_ecr_repository" "app_repo" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.app_name}-repository"
    Environment = var.environment
  }
}

# Build and push Docker image
resource "docker_image" "app_image" {
  name = "${aws_ecr_repository.app_repo.repository_url}:latest"
  
  build {
    context    = "${path.module}/.."  # Path to your app directory (parent of terraform/)
    dockerfile = "Dockerfile"
    
    # Build arguments if needed
    build_args = {
      ENVIRONMENT = "production"
    }
  }
  
  # Force rebuild on every apply (optional)
  triggers = {
    dir_sha1 = sha1(join("", [for f in fileset("${path.module}/..", "{app.py,requirements.txt,config.py,Dockerfile,.dockerignore}") : filesha1("${path.module}/../${f}")]))
  }

  depends_on = [aws_ecr_repository.app_repo]
}

# Push image to ECR
resource "docker_registry_image" "app_registry_image" {
  name = docker_image.app_image.name

  depends_on = [docker_image.app_image]
}

# ECS Cluster (Simplified - no capacity providers needed for Fargate)
resource "aws_ecs_cluster" "main" {
  name = "main-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "main-ecs-cluster"
  }
}

# VPC endpoints for SSM Session Manager
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public_web_az1.id, aws_subnet.public_web_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  private_dns_enabled = true
  
  tags = {
    Name = "ssm-vpc-endpoint"
  }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public_web_az1.id, aws_subnet.public_web_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  private_dns_enabled = true
  
  tags = {
    Name = "ssmmessages-vpc-endpoint"
  }
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public_web_az1.id, aws_subnet.public_web_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  private_dns_enabled = true
  
  tags = {
    Name = "ec2messages-vpc-endpoint"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/my-app"
  retention_in_days = 14

  tags = {
    Name = "ecs-logs"
    Environment = "production"
  }
}

# ECS Fargate Task Definition
resource "aws_ecs_task_definition" "app" {
  family                   = "my-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  
  cpu    = "256"  # 0.25 vCPU
  memory = "512"  # 512 MB

  container_definitions = jsonencode([
    {
      name      = "my-app"
      image     = docker_registry_image.app_registry_image.name
      essential = true

      # Enable ECS Exec
      linuxParameters = {
        initProcessEnabled = true
      }

      portMappings = [
        {
          containerPort = 5000  # Changed to Flask port
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }

      environment = [
        {
          name  = "DB_HOST"
          value = aws_db_instance.main.endpoint
        },
        {
          name  = "DB_NAME"
          value = aws_db_instance.main.db_name
        },
        {
          name  = "DB_USERNAME"
          value = aws_db_instance.main.username
        },
        {
          name  = "DB_PASSWORD"
          value = var.db_password
        },
        {
          name  = "S3_BUCKET_NAME"
          value = aws_s3_bucket.app_bucket.id
        },
        {
          name  = "S3_REGION"
          value = var.aws_region
        },
        {
          name  = "AWS_DEFAULT_REGION"
          value = "us-east-1"
        },
        {
          name  = "FLASK_ENV"
          value = "production"
        }
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:5000/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = {
    Name = "my-app-task-definition"
    Environment = "production"
  }
}

# Application Load Balancer
resource "aws_lb" "main_alb" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_web_az1.id, aws_subnet.public_web_az2.id]

  enable_deletion_protection = false

  depends_on = [aws_internet_gateway.igw]

  tags = {
    Name = "main-alb"
  }
}

# Target Group for Fargate
resource "aws_lb_target_group" "ecs_tg" {
  name        = "ecs-target-group"
  port        = 5000  # Changed to Flask port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"  # IP targets for Fargate

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"  # Flask health endpoint
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name = "ecs-target-group"
  }
}

# Load Balancer Listener
resource "aws_lb_listener" "main_listener" {
  load_balancer_arn = aws_lb.main_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs_tg.arn
  }
}

# ECS Fargate Service
resource "aws_ecs_service" "main" {
  name            = "my-app-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = [aws_subnet.public_web_az1.id, aws_subnet.public_web_az2.id]
    security_groups  = [aws_security_group.ecs_fargate_sg.id]
    assign_public_ip = true  # Required for Fargate in public subnets
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ecs_tg.arn
    container_name   = "my-app"
    container_port   = 5000  # Changed to Flask port
  }

  depends_on = [aws_lb_listener.main_listener]

  tags = {
    Name = "my-app-ecs-service"
    Environment = "production"
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

# Application Auto Scaling Target for ECS Service
resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# Application Auto Scaling Policy - CPU
resource "aws_appautoscaling_policy" "ecs_policy_cpu" {
  name               = "cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Application Auto Scaling Policy - Memory
resource "aws_appautoscaling_policy" "ecs_policy_memory" {
  name               = "memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value = 80.0
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet-group"
  subnet_ids = [aws_subnet.private_db_az1.id, aws_subnet.private_db_az2.id]

  tags = {
    Name = "main-db-subnet-group"
  }
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "${var.app_name}-database"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 20
  storage_type          = "gp2"
  storage_encrypted     = true
  
  db_name  = replace(var.app_name, "-", "")
  username = "admin"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  multi_az               = false
  publicly_accessible    = false
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = true
  deletion_protection = false
  
  performance_insights_enabled = false
  
  tags = {
    Name        = "${var.app_name}-database"
    Environment = var.environment
  }
}

# CloudWatch Monitoring for Fargate and ALB

# SNS Topic for Alerts (if email is provided)
resource "aws_sns_topic" "alerts" {
  count = var.alert_email != "" ? 1 : 0
  name  = "${var.app_name}-alerts"

  tags = {
    Name        = "${var.app_name}-alerts"
    Environment = var.environment
  }
}

# SNS Topic Subscription for Email Alerts
resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch Alarms for ALB

# ALB - High Response Time
resource "aws_cloudwatch_metric_alarm" "alb_response_time" {
  alarm_name          = "${var.app_name}-alb-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "This metric monitors ALB response time"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    LoadBalancer = aws_lb.main_alb.arn_suffix
  }

  tags = {
    Name        = "${var.app_name}-alb-response-time-alarm"
    Environment = var.environment
  }
}

# ALB - High Error Rate (5xx)
resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  alarm_name          = "${var.app_name}-alb-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors ALB 5xx errors"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    LoadBalancer = aws_lb.main_alb.arn_suffix
  }

  tags = {
    Name        = "${var.app_name}-alb-5xx-errors-alarm"
    Environment = var.environment
  }
}

# ALB - Unhealthy Targets
resource "aws_cloudwatch_metric_alarm" "alb_unhealthy_targets" {
  alarm_name          = "${var.app_name}-alb-unhealthy-targets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "This metric monitors unhealthy targets"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    TargetGroup  = aws_lb_target_group.ecs_tg.arn_suffix
    LoadBalancer = aws_lb.main_alb.arn_suffix
  }

  tags = {
    Name        = "${var.app_name}-alb-unhealthy-targets-alarm"
    Environment = var.environment
  }
}

# CloudWatch Alarms for ECS Fargate

# ECS - High CPU Utilization
resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  alarm_name          = "${var.app_name}-ecs-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ECS CPU utilization"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    ServiceName = aws_ecs_service.main.name
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = {
    Name        = "${var.app_name}-ecs-cpu-high-alarm"
    Environment = var.environment
  }
}

# ECS - High Memory Utilization
resource "aws_cloudwatch_metric_alarm" "ecs_memory_high" {
  alarm_name          = "${var.app_name}-ecs-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors ECS memory utilization"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    ServiceName = aws_ecs_service.main.name
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = {
    Name        = "${var.app_name}-ecs-memory-high-alarm"
    Environment = var.environment
  }
}

# ECS - Service Running Task Count
resource "aws_cloudwatch_metric_alarm" "ecs_running_tasks_low" {
  alarm_name          = "${var.app_name}-ecs-running-tasks-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "RunningTaskCount"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors ECS running task count"
  alarm_actions       = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []

  dimensions = {
    ServiceName = aws_ecs_service.main.name
    ClusterName = aws_ecs_cluster.main.name
  }

  tags = {
    Name        = "${var.app_name}-ecs-running-tasks-low-alarm"
    Environment = var.environment
  }
}

# AWS WAF v2 Web ACL
resource "aws_wafv2_web_acl" "main" {
  name  = "${var.app_name}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Core Rule Set (with overrides for common false positives)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Override rules that commonly cause false positives for web applications
        rule_action_override {
          action_to_use {
            count {} # Count instead of block for testing
          }
          name = "SizeRestrictions_BODY"
        }

        rule_action_override {
          action_to_use {
            count {} # Count instead of block for file uploads
          }
          name = "GenericRFI_BODY"
        }

        rule_action_override {
          action_to_use {
            count {} # Count instead of block for form submissions
          }
          name = "CrossSiteScripting_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Known Bad Inputs (less likely to cause false positives)
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Amazon IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AmazonIpReputationListMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Rate limiting to prevent abuse (adjust rate as needed)
  rule {
    name     = "RateLimitRule"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000 # Requests per 5-minute window per IP
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRuleMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Allow specific paths that might be blocked (customize as needed)
  rule {
    name     = "AllowSpecificPaths"
    priority = 0 # Higher priority (lower number) = evaluated first

    action {
      allow {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "/upload"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "STARTS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = "/api/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "STARTS_WITH"
          }
        }
        statement {
          byte_match_statement {
            search_string = "/health"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "EXACTLY"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowSpecificPathsMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name        = "${var.app_name}-web-acl"
    Environment = var.environment
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.app_name}WebAcl"
    sampled_requests_enabled   = true
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/wafv2/${var.app_name}"
  retention_in_days = 14

  tags = {
    Name        = "${var.app_name}-waf-logs"
    Environment = var.environment
  }
}

# WAF Logging Configuration
resource "aws_cloudwatch_log_resource_policy" "waf_logs_policy" {
  policy_name = "AWSWAFLoggingPolicy"
  policy_document = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AWSWAFLogs",
        Effect = "Allow",
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        },
        Action = "logs:PutLogEvents",
        Resource = "${aws_cloudwatch_log_group.waf_logs.arn}:*"
      }
    ]
  })
}

# WAF CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests" {
  count               = var.alert_email != "" ? 1 : 0
  alarm_name          = "${var.app_name}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "High number of requests blocked by WAF"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = var.aws_region
  }

  tags = {
    Name        = "${var.app_name}-waf-blocked-requests-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_rate_limit_triggered" {
  count               = var.alert_email != "" ? 1 : 0
  alarm_name          = "${var.app_name}-waf-rate-limit"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RateLimitRuleMetric"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Rate limiting is being triggered frequently"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = var.aws_region
  }

  tags = {
    Name        = "${var.app_name}-waf-rate-limit-alarm"
    Environment = var.environment
  }
}

# Update the main CloudWatch dashboard to include WAF metrics
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "your-dashboard-name"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.main_alb.arn_suffix],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_ELB_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "ALB Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.ecs_tg.arn_suffix],
            [".", "UnHealthyHostCount", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Target Health"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ServiceName", aws_ecs_service.main.name, "ClusterName", aws_ecs_cluster.main.name],
            [".", "MemoryUtilization", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "ECS Resource Utilization"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ECS", "RunningTaskCount", "ServiceName", aws_ecs_service.main.name, "ClusterName", aws_ecs_cluster.main.name],
            [".", "PendingTaskCount", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "ECS Task Counts"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.aws_region],
            [".", "BlockedRequests", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "WAF Request Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "CommonRuleSetMetric", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.aws_region],
            [".", "RateLimitRuleMetric", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "WAF Rule Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Admin IAM User with full administrative access
resource "aws_iam_user" "admin_user" {
  count = var.create_admin_user ? 1 : 0
  name  = "${var.app_name}-admin-user"
  path  = "/"

  tags = {
    Name        = "${var.app_name}-admin-user"
    Environment = var.environment
    Role        = "Administrator"
  }
}

# IAM User for Console Access (optional)
resource "aws_iam_user" "console_user" {
  count = var.create_iam_user ? 1 : 0
  name  = "${var.app_name}-console-user"
  path  = "/"

  tags = {
    Name        = "${var.app_name}-console-user"
    Environment = var.environment
  }
}

# Admin User Login Profile for Console Access
resource "aws_iam_user_login_profile" "admin_user_profile" {
  count           = var.create_admin_user ? 1 : 0
  user            = aws_iam_user.admin_user[0].name
  password_length = 20

  # Force user to change password on first login
  password_reset_required = true

  lifecycle {
    ignore_changes = [password_reset_required]
  }
}

# Admin User Access Key for Programmatic Access
resource "aws_iam_access_key" "admin_user_key" {
  count = var.create_admin_user ? 1 : 0
  user  = aws_iam_user.admin_user[0].name
}

# Attach AdministratorAccess policy to admin user
resource "aws_iam_user_policy_attachment" "admin_user_policy" {
  count      = var.create_admin_user ? 1 : 0
  user       = aws_iam_user.admin_user[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# IAM User Login Profile for Console Access
resource "aws_iam_user_login_profile" "console_user_profile" {
  count           = var.create_iam_user ? 1 : 0
  user            = aws_iam_user.console_user[0].name
  password_length = 20

  # Force user to change password on first login
  password_reset_required = true

  lifecycle {
    ignore_changes = [password_reset_required]
  }
}

# IAM Access Key for Programmatic Access
resource "aws_iam_access_key" "console_user_key" {
  count = var.create_iam_user ? 1 : 0
  user  = aws_iam_user.console_user[0].name
}

# IAM Policy for application management (developer)
resource "aws_iam_policy" "app_management_policy" {
  count = var.create_iam_user ? 1 : 0
  name  = "${var.app_name}-management-policy"
  path  = "/"
  
  description = "Policy for managing application resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # IAM Self-Service permissions
      {
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:GetLoginProfile"
        ]
        Resource = "*"
      },
      # ECS permissions
      {
        Effect = "Allow"
        Action = [
          "ecs:*",
          "ecr:*"
        ]
        Resource = "*"
      },
      # CloudWatch permissions
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:*",
          "logs:*"
        ]
        Resource = "*"
      },
      # Load Balancer permissions
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:*"
        ]
        Resource = "*"
      },
      # RDS permissions
      {
        Effect = "Allow"
        Action = [
          "rds:Describe*",
          "rds:ListTagsForResource",
          "rds:ModifyDBInstance",
          "rds:RebootDBInstance"
        ]
        Resource = "*"
      },
      # S3 permissions
      {
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      },
      # Systems Manager (for ECS Exec and EC2 SSM)
      {
        Effect = "Allow"
        Action = [
          "ssm:*",
          "ssmmessages:*",
          "ec2messages:*"
        ]
        Resource = "*"
      },
      # EC2 permissions (for SSM access to DB admin instance)
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus"
        ]
        Resource = "*"
      },
      # WAF permissions
      {
        Effect = "Allow"
        Action = [
          "wafv2:GetWebACL",
          "wafv2:GetSampledRequests",
          "wafv2:ListWebACLs"
        ]
        Resource = "*"
      },
      # Auto Scaling permissions
      {
        Effect = "Allow"
        Action = [
          "application-autoscaling:*"
        ]
        Resource = "*"
      },
      # SNS permissions (for alerts)
      {
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:ListTopics",
          "sns:ListSubscriptions"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.app_name}-management-policy"
    Environment = var.environment
  }
}

# Attach policy to user
resource "aws_iam_user_policy_attachment" "console_user_policy" {
  count      = var.create_iam_user ? 1 : 0
  user       = aws_iam_user.console_user[0].name
  policy_arn = aws_iam_policy.app_management_policy[0].arn
}

# Outputs
output "alb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.main_alb.dns_name
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "ecr_repository_url" {
  description = "ECR repository URL"
  value       = aws_ecr_repository.app_repo.repository_url
}

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.app_bucket.id
}

output "db_admin_instance_id" {
  description = "Instance ID for database administration (use with SSM)"
  value       = aws_instance.db_admin.id
}

output "ssm_session_command" {
  description = "Command to connect to database admin instance via SSM"
  value       = "aws ssm start-session --target ${aws_instance.db_admin.id}"
}

output "ecs_exec_commands" {
  description = "Commands to debug running containers"
  value = <<-EOT
    # One-liner to connect to first available container:
    TASK_ID=$(aws ecs list-tasks --cluster ${aws_ecs_cluster.main.name} --service ${aws_ecs_service.main.name} --query 'taskArns[0]' --output text | cut -d'/' -f3) && aws ecs execute-command --cluster ${aws_ecs_cluster.main.name} --task $TASK_ID --container my-app --interactive --command "/bin/bash"
    
    # Or step by step:
    # 1. List running tasks:
    aws ecs list-tasks --cluster ${aws_ecs_cluster.main.name} --service ${aws_ecs_service.main.name}
    
    # 2. Connect to specific task (replace TASK_ID):
    aws ecs execute-command --cluster ${aws_ecs_cluster.main.name} --task TASK_ID --container my-app --interactive --command "/bin/bash"
    
    # Example debugging commands inside container:
    # - Check application logs: cat /var/log/app.log
    # - Test database connection: mysql -h DB_HOST -u ${aws_db_instance.main.username} -p
    # - Check app health: curl http://localhost/
    # - View environment: env | grep DB_
  EOT
}

output "rds_connection_info" {
  description = "RDS connection information"
  value = {
    endpoint = aws_db_instance.main.endpoint
    database = aws_db_instance.main.db_name
    username = aws_db_instance.main.username
    port     = aws_db_instance.main.port
  }
  sensitive = true
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = var.alert_email != "" ? aws_sns_topic.alerts[0].arn : "No email provided - alerts disabled"
}

output "monitoring_info" {
  description = "Monitoring setup information"
  value = {
    dashboard_name = aws_cloudwatch_dashboard.main.dashboard_name
    alarms_created = [
      aws_cloudwatch_metric_alarm.alb_response_time.alarm_name,
      aws_cloudwatch_metric_alarm.alb_5xx_errors.alarm_name,
      aws_cloudwatch_metric_alarm.alb_unhealthy_targets.alarm_name,
      aws_cloudwatch_metric_alarm.ecs_cpu_high.alarm_name,
      aws_cloudwatch_metric_alarm.ecs_memory_high.alarm_name,
      aws_cloudwatch_metric_alarm.ecs_running_tasks_low.alarm_name,
      var.alert_email != "" ? aws_cloudwatch_metric_alarm.waf_blocked_requests[0].alarm_name : "WAF alarms disabled",
      var.alert_email != "" ? aws_cloudwatch_metric_alarm.waf_rate_limit_triggered[0].alarm_name : "WAF alarms disabled"
    ]
    email_alerts = var.alert_email != "" ? "Enabled" : "Disabled (no email provided)"
    waf_enabled = "Yes"
  }
}

# Additional outputs for WAF
output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_monitoring_info" {
  description = "WAF monitoring information"
  value = {
    web_acl_name = aws_wafv2_web_acl.main.name
    log_group    = aws_cloudwatch_log_group.waf_logs.name
    cloudwatch_dashboard_url = "https://${var.aws_region}.console.aws.amazon.com/wafv2/homev2/web-acl/${aws_wafv2_web_acl.main.name}/${aws_wafv2_web_acl.main.id}/overview?region=${var.aws_region}"
  }
}

# Output the credentials (sensitive)
output "iam_user_credentials" {
  description = "IAM user credentials for console and programmatic access"
  value = var.create_iam_user ? {
    username    = aws_iam_user.console_user[0].name
    console_url = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
    access_key  = aws_iam_access_key.console_user_key[0].id
    secret_key  = aws_iam_access_key.console_user_key[0].secret
    password    = aws_iam_user_login_profile.console_user_profile[0].password
  } : null
  sensitive = true
}

output "console_login_instructions" {
  description = "Instructions for console login"
  value = var.create_iam_user ? format(
    "1. Go to: https://%s.signin.aws.amazon.com/console\n2. Account ID: %s\n3. Username: %s\n4. Password: (shown in sensitive output - run 'terraform output iam_user_credentials')\n5. You'll be required to change the password on first login\n\nFor programmatic access, use the access key and secret key from the sensitive output.",
    data.aws_caller_identity.current.account_id,
    data.aws_caller_identity.current.account_id,
    aws_iam_user.console_user[0].name
  ) : "IAM user not created (create_iam_user = false)"
}

output "admin_user_credentials" {
  description = "Admin IAM user credentials with full AWS access"
  value = var.create_admin_user ? {
    username    = aws_iam_user.admin_user[0].name
    console_url = "https://${data.aws_caller_identity.current.account_id}.signin.aws.amazon.com/console"
    access_key  = aws_iam_access_key.admin_user_key[0].id
    secret_key  = aws_iam_access_key.admin_user_key[0].secret
    password    = aws_iam_user_login_profile.admin_user_profile[0].password
  } : null
  sensitive = true
}

output "admin_login_instructions" {
  description = "Instructions for admin console login"
  value = var.create_admin_user ? format(
    "ADMIN USER ACCESS:\n1. Go to: https://%s.signin.aws.amazon.com/console\n2. Account ID: %s\n3. Username: %s\n4. Password: (shown in sensitive output - run 'terraform output admin_user_credentials')\n5. You'll be required to change the password on first login\n\nWARNING: This user has FULL administrative access to your AWS account!\n\nFor programmatic access, use the access key and secret key from the sensitive output.",
    data.aws_caller_identity.current.account_id,
    data.aws_caller_identity.current.account_id,
    aws_iam_user.admin_user[0].name
  ) : "Admin IAM user not created (create_admin_user = false)"
}