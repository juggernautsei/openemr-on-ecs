"""Tarevo SaaS component modules for Sprint 4.

Each module owns a distinct infrastructure concern:

  network         VPC, security groups, internet-facing ALB, WAF WebACL
  security        KMS encryption key, ACM wildcard certificate
  database        Shared Aurora Serverless v2 cluster, Valkey Serverless,
                  DynamoDB tenant-registry table
  compute         Shared ECS cluster (Fargate capacity providers)
  provisioner     Lambda + Custom Resource that creates/drops per-tenant
                  MySQL databases on the shared Aurora cluster
  tenant_resources  Per-tenant EFS pair, backup plan, Fargate service,
                  ALB listener rule, Route53 alias record
"""
