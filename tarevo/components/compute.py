"""Compute component — shared ECS cluster."""

from typing import Optional

from aws_cdk import RemovalPolicy
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ssm as ssm
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import SSM_CLUSTER_ARN, SSM_CLUSTER_NAME


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
        """Create the shared ECS cluster with enhanced Container Insights and
        Fargate Spot + On-Demand capacity providers.

        Container Insights V2 (Enhanced):
            Publishes CPU, memory, network, and storage metrics per task and
            per service to CloudWatch.  The enhanced tier also includes
            application signals and operational dashboards.

        ECS Exec:
            Enabled for break-glass access to running containers.  All session
            traffic is encrypted with the platform KMS key and logged to a
            dedicated CloudWatch log group (/tarevo/ecs/exec) with 1-year
            retention.

        Capacity providers:
            FARGATE and FARGATE_SPOT are both registered.  Each TenantStack
            chooses its provider strategy (e.g. 100% On-Demand for prod,
            mixed Spot for dev tenants).

        Returns:
            The created Cluster.
        """
        exec_log_group = logs.LogGroup(
            self.scope,
            "EcsExecLogGroup",
            log_group_name="/tarevo/ecs/exec",
            encryption_key=kms_key,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.DESTROY,
        )

        cluster = ecs.Cluster(
            self.scope,
            "EcsCluster",
            cluster_name="tarevo-shared",
            vpc=vpc,
            container_insights_v2=ecs.ContainerInsights.ENHANCED,
            enable_fargate_capacity_providers=True,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                kms_key=kms_key,
                log_configuration=ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=exec_log_group,
                    cloud_watch_encryption_enabled=True,
                ),
                logging=ecs.ExecuteCommandLogging.OVERRIDE,
            ),
        )

        ssm.StringParameter(
            self.scope,
            "ClusterArnParam",
            parameter_name=SSM_CLUSTER_ARN,
            string_value=cluster.cluster_arn,
            description="Tarevo shared ECS cluster ARN",
        )
        ssm.StringParameter(
            self.scope,
            "ClusterNameParam",
            parameter_name=SSM_CLUSTER_NAME,
            string_value=cluster.cluster_name,
            description="Tarevo shared ECS cluster name",
        )

        NagSuppressions.add_resource_suppressions(
            cluster,
            [
                {
                    "id": "AwsSolutions-ECS4",
                    "reason": (
                        "Container Insights V2 (Enhanced) is enabled via "
                        "container_insights_v2=ContainerInsights.ENHANCED.  "
                        "The nag rule checks for the legacy CloudWatch Container "
                        "Insights flag; the V2 enhanced setting supersedes it."
                    ),
                },
                {
                    "id": "AwsSolutions-ECS7",
                    "reason": (
                        "Container Insights V2 (Enhanced) is enabled.  This "
                        "supersedes the legacy ContainerInsights=enabled setting "
                        "that the nag rule inspects."
                    ),
                },
            ],
        )

        # The exec log group’s KMS key requires that ECS’s service principal
        # can use it.  CDK generates an inline key policy for the grant;
        # suppress the corresponding IAM nag.
        NagSuppressions.add_resource_suppressions(
            exec_log_group,
            [
                {
                    "id": "HIPAA.Security-CloudWatchLogGroupKMSEncrypted",
                    "reason": "EcsExecLogGroup IS encrypted with the platform KMS key.",
                },
            ],
        )

        self.cluster = cluster
        return cluster
