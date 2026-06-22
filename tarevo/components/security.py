"""Security component — KMS encryption key and ACM wildcard certificate."""

from typing import Optional

from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_kms as kms
from aws_cdk import aws_route53 as route53
from constructs import Construct

from ..constants import DOMAIN


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

    # ── KMS ───────────────────────────────────────────────────────────────────

    def create_kms_key(self) -> kms.Key:
        """Create a single platform KMS key used for all encrypted resources.

        Returns:
            The created KMS key.

        TODO Sprint 4.1:
            - enable_key_rotation=True
            - removal_policy=DESTROY, pending_window=7 days
            - Grant encrypt/decrypt to logs.<region>.amazonaws.com,
              s3.amazonaws.com, rds.amazonaws.com, elasticache.amazonaws.com
        """
        raise NotImplementedError("TODO Sprint 4.1: implement create_kms_key()")

    # ── Certificate ───────────────────────────────────────────────────────────

    def create_certificate(self, zone: route53.IHostedZone) -> acm.Certificate:
        """Create ACM wildcard certificate for *.tarevoehr.app.

        DNS validation is automatic via Route53 (no manual CNAME needed).

        Returns:
            The created certificate.

        TODO Sprint 4.2:
            - domain_name=f"*.{DOMAIN}"
            - validation=CertificateValidation.from_dns(zone)
        """
        raise NotImplementedError("TODO Sprint 4.2: implement create_certificate()")
