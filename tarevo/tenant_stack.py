"""TenantStack — per-tenant Fargate service wired to the shared ALB.

Sprint 3 PoC design:
  - Uses L2 `ecs.FargateService` directly (not the L3 ApplicationLoadBalancedFargateService)
  - Each tenant gets its own: TaskDef, Security Group, TargetGroup, ListenerRule, Route53 record
  - Shared across tenants: VPC, ALB, HTTPS listener, ECS cluster (all from SharedInfraStack)
  - Container image: public nginx (lightweight PoC stub — no ECR needed)
  - ALB terminates TLS; container runs plain HTTP on port 80
  - ARM64 / Graviton to match Sprint 4+ production Fargate target

Listener rule priorities:
  Callers must supply a unique integer priority (100 per tenant, staggered by 100).

Usage in app.py:
    shared = SharedInfraStack(...)
    TenantStack(app, "TarevoTenant-test-a", shared=shared,
                tenant_id="test-a", listener_priority=100, env=env)
    TenantStack(app, "TarevoTenant-test-b", shared=shared,
                tenant_id="test-b", listener_priority=200, env=env)
"""

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as route53_targets
from cdk_nag import NagSuppressions
from constructs import Construct

from .shared_infra_stack import DOMAIN, SharedInfraStack

# Public nginx image from ECR Public (no auth required, no ECR cost)
STUB_IMAGE = "public.ecr.aws/nginx/nginx:alpine-slim"
CONTAINER_PORT = 80  # ALB → container over plain HTTP (TLS terminates at ALB)


class TenantStack(Stack):
    """Per-tenant Fargate workload attached to the shared ALB."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        shared: SharedInfraStack,
        tenant_id: str,
        listener_priority: int,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        hostname = f"{tenant_id}.{DOMAIN}"

        # ── Task security group ───────────────────────────────────────────────
        # Allow ingress from the shared ALB SG on the container port only.
        task_sg = ec2.SecurityGroup(
            self,
            "TaskSg",
            vpc=shared.vpc,
            description=f"ECS task SG for tenant {tenant_id}",
            allow_all_outbound=True,  # tasks need to pull images + reach ECR
        )
        task_sg.add_ingress_rule(
            shared.alb_sg,
            ec2.Port.tcp(CONTAINER_PORT),
            f"Allow ALB to reach {tenant_id} container",
        )
        # NOTE: No egress rule is added to shared.alb_sg here.
        # Modifying a SharedInfraStack SG from TenantStack causes a circular
        # cross-stack dependency.  The ALB SG uses allow_all_outbound=True so it
        # can forward to any per-tenant target group without an explicit rule.

        # ── CloudWatch log group ──────────────────────────────────────────────
        log_group = logs.LogGroup(
            self,
            "LogGroup",
            retention=logs.RetentionDays.ONE_WEEK,
        )
        NagSuppressions.add_resource_suppressions(
            log_group,
            [
                {
                    "id": "HIPAA.Security-CloudWatchLogGroupEncrypted",
                    "reason": "PoC log group — KMS encryption not required for stub container logs.",
                },
                {
                    "id": "HIPAA.Security-CloudWatchLogGroupRetentionPeriod",
                    "reason": "PoC log group — 1-week retention is acceptable for throwaway PoC.",
                },
            ],
        )

        # ── Fargate task definition (L2) ─────────────────────────────────────
        task_role = iam.Role(
            self,
            "TaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description=f"ECS task role for tenant {tenant_id}",
        )
        exec_role = iam.Role(
            self,
            "ExecRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description=f"ECS execution role for tenant {tenant_id}",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                )
            ],
        )
        NagSuppressions.add_resource_suppressions(
            exec_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "AmazonECSTaskExecutionRolePolicy is the standard managed policy required for Fargate task execution.",
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            ],
            apply_to_children=True,
        )
        task_def = ecs.FargateTaskDefinition(
            self,
            "TaskDef",
            cpu=256,
            memory_limit_mib=512,
            task_role=task_role,
            execution_role=exec_role,
            # ARM64 / Graviton — matches Sprint 4+ production target
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64,
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
            ),
        )

        task_def.add_container(
            "nginx",
            image=ecs.ContainerImage.from_registry(STUB_IMAGE),
            port_mappings=[ecs.PortMapping(container_port=CONTAINER_PORT)],
            essential=True,
            # Structured logging to CloudWatch
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=tenant_id,
                log_group=log_group,
            ),
            # Minimal health-check at container level
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "curl -sf http://localhost/ || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(10),
            ),
        )

        NagSuppressions.add_resource_suppressions(
            task_def,
            [
                {
                    "id": "AwsSolutions-ECS2",
                    "reason": "No secrets are injected — stub nginx container needs no environment secrets.",
                }
            ],
        )

        # add_container causes CDK to create an inline DefaultPolicy on the execution
        # role for CloudWatch Logs permissions.  Suppress the HIPAA inline-policy
        # finding via explicit path (must be after add_container so the node exists).
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{construct_id}/ExecRole/DefaultPolicy/Resource",
            [
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "CDK automatically generates an inline DefaultPolicy on the execution role "
                        "for CloudWatch Logs permissions (CreateLogGroup, CreateLogStream, PutLogEvents). "
                        "This is CDK-generated and follows least-privilege principles for Fargate logging."
                    ),
                },
            ],
        )

        # ── Fargate service (L2) — NOT ApplicationLoadBalancedFargateService ──
        service = ecs.FargateService(
            self,
            "Service",
            cluster=shared.cluster,
            task_definition=task_def,
            security_groups=[task_sg],
            desired_count=1,
            # Keep 100% healthy during deploy so no downtime (1 task minimum)
            min_healthy_percent=100,
            max_healthy_percent=200,
            # Deploy in private subnets; ALB handles internet ingress
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            enable_execute_command=False,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
        )

        NagSuppressions.add_resource_suppressions(
            service,
            [
                {
                    "id": "AwsSolutions-ECS4",
                    "reason": "Container insights are enabled at cluster level in SharedInfraStack.",
                }
            ],
        )

        # ── ALB target group ─────────────────────────────────────────────────
        target_group = elb.ApplicationTargetGroup(
            self,
            "TargetGroup",
            vpc=shared.vpc,
            port=CONTAINER_PORT,
            protocol=elb.ApplicationProtocol.HTTP,
            target_type=elb.TargetType.IP,
            health_check=elb.HealthCheck(
                path="/",
                healthy_http_codes="200",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
            deregistration_delay=Duration.seconds(30),
        )

        # Register Fargate service with the target group
        service.attach_to_application_target_group(target_group)

        # ── Listener rule — host-header routing ──────────────────────────────
        elb.ApplicationListenerRule(
            self,
            "ListenerRule",
            listener=shared.https_listener,
            priority=listener_priority,
            conditions=[elb.ListenerCondition.host_headers([hostname])],
            action=elb.ListenerAction.forward([target_group]),
        )

        # ── Route53 A alias → shared ALB ─────────────────────────────────────
        # Re-lookup the zone in this stack's context (cross-stack lookup not needed)
        zone = route53.HostedZone.from_lookup(
            self,
            "TarevoZone",
            domain_name=DOMAIN,
        )

        route53.ARecord(
            self,
            "AliasRecord",
            zone=zone,
            record_name=tenant_id,
            target=route53.RecordTarget.from_alias(
                route53_targets.LoadBalancerTarget(shared.alb)
            ),
        )

        # ── Outputs ───────────────────────────────────────────────────────────
        CfnOutput(self, "TenantUrl", value=f"https://{hostname}")
        CfnOutput(self, "ServiceName", value=service.service_name)
