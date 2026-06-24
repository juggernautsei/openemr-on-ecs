"""Security component — KMS encryption key and ACM wildcard certificate."""

from typing import Optional

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_ssm as ssm
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import DOMAIN, SSM_KMS_KEY_ARN


class SecurityComponents:
    """Creates the platform KMS key and ACM wildcard certificate.

    Build order (called from SharedInfraStack.__init__):
      1. create_kms_key()
      2. create_certificate(zone)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_kms_key()
        self.kms_key: Optional[kms.Key] = None

        # Set by create_certificate()
        self.certificate: Optional[acm.Certificate] = None

    # ── KMS ─────────────────────────────────────────────────────────────────────

    def create_kms_key(self) -> kms.Key:
        """Create a single platform CMK used by all encrypted resources.

        One key is shared across Aurora, Valkey, EFS, S3 access-log bucket,
        CloudWatch Log Groups, DynamoDB, and Secrets Manager.  A single key
        simplifies grant management and keeps costs low (one key = $1/month).

        Rotation:
            Annual automatic rotation is enabled (HIPAA requirement).

        Removal policy:
            DESTROY with a 7-day pending window so ``cdk destroy`` works
            cleanly during sprints.  Change to RETAIN before production.

        Service key-policy grants:
            CloudWatch Logs requires an explicit key-policy statement
            (KMS resource policy) because it uses a service-linked role
            that cannot be granted via IAM alone.

            All other AWS services (RDS, ElastiCache, EFS, Backup, S3)
            receive their grants automatically when the key is passed to
            the respective CDK L2 constructs.

        Returns:
            The created KMS Key.
        """
        key = kms.Key(
            self.scope,
            "PlatformKey",
            description="Tarevo platform CMK — Aurora, Valkey, EFS, S3, CW Logs, DDB, SecretsManager",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
            pending_window=Duration.days(7),
        )

        # CloudWatch Logs service principal needs an explicit key-policy entry.
        # This cannot be satisfied with IAM alone because CW Logs writes using
        # a service-linked principal, not a role that we can grant to.
        region = Stack.of(self.scope).region
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsEncryption",
                principals=[iam.ServicePrincipal(f"logs.{region}.amazonaws.com")],
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                resources=["*"],
            )
        )

        NagSuppressions.add_resource_suppressions(
            key,
            [
                {
                    "id": "HIPAA.Security-KMSBackingKeyRotationEnabled",
                    "reason": "Annual automatic rotation IS enabled (enable_key_rotation=True).",
                },
            ],
        )

        ssm.StringParameter(
            self.scope,
            "KmsKeyArnParam",
            parameter_name=SSM_KMS_KEY_ARN,
            string_value=key.key_arn,
            description="Platform CMK ARN — used by TenantStack to encrypt EFS and Secrets Manager",
        )

        self.kms_key = key
        return key

    # ── Certificate ───────────────────────────────────────────────────────────

    def create_certificate(self, zone: route53.IHostedZone) -> acm.Certificate:
        """Create ACM wildcard certificate for *.tarevoehr.app.

        DNS validation is fully automated via Route53 — CDK creates the
        validation CNAME record in the hosted zone.  No manual steps.

        The certificate covers every tenant subdomain: acme.tarevoehr.app,
        demo.tarevoehr.app, etc.

        Returns:
            The created ACM Certificate.
        """
        cert = acm.Certificate(
            self.scope,
            "WildcardCert",
            domain_name=f"*.{DOMAIN}",
            validation=acm.CertificateValidation.from_dns(zone),
        )

        self.certificate = cert
        return cert
