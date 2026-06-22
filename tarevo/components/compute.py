"""Compute component — shared ECS cluster."""

from typing import Optional

from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_kms as kms
from constructs import Construct


class ComputeComponents:
    """Creates the shared ECS cluster used by every tenant's Fargate service.

    Build order (called from SharedInfraStack.__init__):
      1. create_cluster(vpc, kms_key)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_cluster()
        self.cluster: Optional[ecs.Cluster] = None

    def create_cluster(self, vpc: ec2.Vpc, kms_key: kms.Key) -> ecs.Cluster:
        """Create the ECS cluster with container insights and Fargate capacity providers.

        Returns:
            The created Cluster.

        TODO Sprint 4.6:
            - container_insights_v2=ContainerInsights.ENHANCED
            - enable_fargate_capacity_providers=True
            - execute_command_configuration with KMS + CloudWatch logging
            - Store cluster ARN and name in SSM
            - Suppress AwsSolutions-ECS4 (insights enabled at cluster level)
        """
        raise NotImplementedError("TODO Sprint 4.6: implement create_cluster()")
