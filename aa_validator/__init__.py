#!/usr/bin/env python3
"""Validate AWS identity and resource policies with AWS Access Analyzer"""
import argparse
import dataclasses
import datetime
import enum
import functools
import json
import logging
from typing import TYPE_CHECKING, Generator, List, Iterable, Optional, Union

import boto3
import boto3.session
import botocore.exceptions
import pydash  # type: ignore

if TYPE_CHECKING:  # pragma: no cover
    from mypy_boto3_iam.type_defs import PolicyDocumentDictTypeDef


class ResourceType(str, enum.Enum):
    """Resource types."""

    ECR_REPOSITORY = "AWS::ECR::Repository"
    IAM_GROUP = "AWS::IAM::Group"
    IAM_POLICY = "AWS::IAM::Policy"
    IAM_ROLE = "AWS::IAM::Role"
    IAM_USER = "AWS::IAM::User"
    S3_BUCKET = "AWS::S3::Bucket"
    SNS_TOPIC = "AWS::SNS::Topic"
    SQS_QUEUE = "AWS::SQS::Queue"


class PolicyType(str, enum.Enum):
    """Policy types."""

    IDENTITY_POLICY = "IDENTITY_POLICY"
    RESOURCE_POLICY = "RESOURCE_POLICY"


@dataclasses.dataclass
class Finding:
    """Access Analyzer Finding"""

    finding_type: str
    finding_details: str
    issue_code: str
    learn_more_link: str


@dataclasses.dataclass
class Policy:
    """Identity or resource policy."""

    policy_type: PolicyType
    policy_name: str
    policy_document: Union["PolicyDocumentDictTypeDef", dict, str]
    findings: List[Finding] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        # Ensure policy document is parsed dict, not a string
        self.policy_document = _parse_doc(self.policy_document)

    def add_finding(self, finding: Finding):
        """Add a finding to this policy."""
        self.findings.append(finding)

    @property
    def doc(self) -> str:
        """Serialized policy document"""
        return json.dumps(self.policy_document)

    @property
    def num_findings(self) -> int:
        """Number of findings for this policy."""
        return len(self.findings)


# Resource types that validate_policy() supports in validatePolicyResourceType
# parameter
VALID_VALIDATE_POLICY_RESOURCE_TYPES = {ResourceType.S3_BUCKET}


@dataclasses.dataclass
class Resource:
    """AWS resource."""

    resource_type: ResourceType
    resource_arn: str
    policies: List[Policy] = dataclasses.field(default_factory=list)

    def add_policy(self, policy: Policy):
        """Add a policy to this resource."""
        self.policies.append(policy)

    @property
    def num_findings(self) -> int:
        """Number of findings in policies of this resource"""
        return sum(p.num_findings for p in self.policies)

    @property
    def validate_policy_resource_type(self) -> Optional[str]:
        """Resource type to use for resource policy validation."""
        if self.resource_type in VALID_VALIDATE_POLICY_RESOURCE_TYPES:
            return self.resource_type.value

        return None


def _parse_doc(doc: Union[str, dict]) -> dict:
    """Parse policy document if necessary.

    Args:
        doc: Policy document to parse.

    Returns:
        Parsed policy document.
    """

    if isinstance(doc, (str, bytes)):
        return json.loads(doc)

    return doc


def ignore_permission_errors(func):
    """Catch and ignore AWS API errors caused by insufficient permissions."""

    @functools.wraps(func)
    def wrapper(*_args, **_kwargs):
        try:
            yield from func(*_args, **_kwargs)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] in (
                "AccessDenied",
                "AccessDeniedException",
                "AuthorizationError",
                "InvalidClientTokenId",
                "NotAuthorized",
                "UnrecognizedClientException",
            ):
                reg = _kwargs.get("region_name")
                region = f" on region {reg}" if reg else ""
                logger().warning(
                    "Insufficient permissions to discover policies. Skipping this resource type%s. Reason: %s",
                    region,
                    err,
                )
                return
            raise

        return

    return wrapper


@functools.lru_cache()
def get_regions(service) -> List[str]:
    """Get a list of regions for policy discovery."""
    session = boto3.session.Session()
    available_regions = session.get_available_regions(service)
    requested_regions: str = args().regions

    if requested_regions:
        return sorted(set(available_regions) & set(requested_regions.split(",")))

    return sorted(available_regions)


def for_each_region(service):
    """Decorator to call the given handler for each AWS Region."""

    def inner(func):
        @functools.wraps(func)
        def wrapper(*_args, **_kwargs):
            for region in get_regions(service):
                yield from func(*_args, region_name=region, **_kwargs)

        return wrapper

    return inner


def get_iam_resources() -> Generator[Resource, None, None]:
    """Collect IAM policies from IAM users, groups, roles and customer managed policies.

    Yields:
        Resource objects for each IAM resource.
    """
    logger().info("Collecting IAM user, group, role and customer managed policies.")

    paginator = boto3.client("iam").get_paginator("get_account_authorization_details")
    for page in paginator.paginate(
        Filter=["User", "Role", "Group", "LocalManagedPolicy"]
    ):
        # Users and their inline policies
        for user in page["UserDetailList"]:
            yield Resource(
                ResourceType.IAM_USER,
                user["Arn"],
                [
                    Policy(
                        PolicyType.IDENTITY_POLICY,
                        policy["PolicyName"],
                        policy["PolicyDocument"],
                    )
                    for policy in user.get("UserPolicyList", [])
                ],
            )

        # Groups and their inline policies
        for group in page["GroupDetailList"]:
            yield Resource(
                ResourceType.IAM_GROUP,
                group["Arn"],
                [
                    Policy(
                        PolicyType.IDENTITY_POLICY,
                        policy["PolicyName"],
                        policy["PolicyDocument"],
                    )
                    for policy in group.get("GroupPolicyList", [])
                ],
            )

        # Roles and their inline policies
        for role in page["RoleDetailList"]:
            role_resource = Resource(
                ResourceType.IAM_ROLE,
                role["Arn"],
                [
                    Policy(
                        PolicyType.IDENTITY_POLICY,
                        policy["PolicyName"],
                        policy["PolicyDocument"],
                    )
                    for policy in role.get("RolePolicyList", [])
                ],
            )

            # Also add AssumeRolePolicyDocument
            role_resource.add_policy(
                Policy(
                    PolicyType.RESOURCE_POLICY,
                    "AssumeRolePolicyDocument",
                    role["AssumeRolePolicyDocument"],
                )
            )

            yield role_resource

        # Customer managed IAM policies
        for policy in page["Policies"]:
            # Dig out default version
            versions = policy["PolicyVersionList"]
            default = list(filter(lambda p: p["IsDefaultVersion"], versions))[0]

            yield Resource(
                ResourceType.IAM_POLICY,
                policy["Arn"],
                [
                    Policy(
                        PolicyType.IDENTITY_POLICY,
                        policy["PolicyName"],
                        default["Document"],
                    )
                ],
            )


def get_s3_resources() -> Generator[Resource, None, None]:
    """Collect S3 bucket policies.

    Yields:
        Resource objects for each bucket with a bucket policy.
    """
    logger().info("Collecting S3 bucket policies...")

    client = boto3.client("s3")
    for bucket in client.list_buckets().get("Buckets", []):
        bucket_name = bucket["Name"]
        logger().info("Processing bucket %s", bucket_name)

        try:
            policy = client.get_bucket_policy(Bucket=bucket_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucketPolicy":
                logger().debug("Ignoring bucket %s without bucket policy.", bucket_name)
                continue
            raise

        yield Resource(
            ResourceType.S3_BUCKET,
            f"arn:aws:s3:::{bucket_name}",
            [Policy(PolicyType.RESOURCE_POLICY, "BucketPolicy", policy["Policy"])],
        )


@for_each_region("sqs")
@ignore_permission_errors
def get_sqs_resources(
    region_name: Optional[str] = None,
) -> Generator[Resource, None, None]:
    """Collect SQS queue policies from a given region.

    Args:
        region_name: AWS Region to collect queue policies from.

    Yields:
        Resource objects for each queue with a queue policy.
    """
    logger().info("Collecting SQS queue policies from %s.", region_name)

    client = boto3.client("sqs", region_name=region_name)
    for page in client.get_paginator("list_queues").paginate():
        for queue_url in page.get("QueueUrls", []):
            logger().info("Processing queue %s", queue_url)

            attributes = client.get_queue_attributes(QueueUrl=queue_url).get(
                "Attributes", {}
            )
            policy = attributes.get("Policy")

            if not policy:
                logger().debug("Ignoring queue %s without a queue policy", queue_url)
                continue

            yield Resource(
                ResourceType.SQS_QUEUE,
                attributes["QueueArn"],
                [Policy(PolicyType.RESOURCE_POLICY, "QueuePolicy", policy)],
            )


@for_each_region("sns")
@ignore_permission_errors
def get_sns_resources(region_name=None) -> Generator[Resource, None, None]:
    """Collect SNS topic policies from a given region.

    Args:
        region_name: AWS Region to collect topic policies from.

    Yields:
        Resource objects for each topic with a topic policy.
    """
    logger().info("Collecting SNS topic policies from %s.", region_name)

    client = boto3.client("sns", region_name=region_name)
    for page in client.get_paginator("list_topics").paginate():
        for topic in page.get("Topics", []):
            topic_arn = topic["TopicArn"]
            logger().info("Processing topic %s", topic_arn)

            attributes = client.get_topic_attributes(TopicArn=topic_arn).get(
                "Attributes", {}
            )
            policy = attributes.get("Policy")

            if not policy:
                logger().debug("Ignoring topic %s without a topic policy", topic_arn)
                continue

            yield Resource(
                ResourceType.SNS_TOPIC,
                topic_arn,
                [Policy(PolicyType.RESOURCE_POLICY, "TopicPolicy", policy)],
            )


@for_each_region("ecr")
@ignore_permission_errors
def get_ecr_resources(region_name=None) -> Generator[Resource, None, None]:
    """Collect ECR repository policies from a given region.

    Args:
        region_name: AWS Region to collect repository policies from.

    Yields:
        Resource objects for each repository with a repository policy.
    """
    logger().info("Collecting ECR repository policies from %s.", region_name)

    client = boto3.client("ecr", region_name=region_name)
    for page in client.get_paginator("describe_repositories").paginate():
        for repository in page.get("repositories", []):
            repository_name = repository["repositoryName"]
            repository_arn = repository["repositoryArn"]
            logger().info("Processing repository %s", repository_arn)

            try:
                policy = client.get_repository_policy(
                    repositoryName=repository_name
                ).get("policyText")
            except client.exceptions.RepositoryPolicyNotFoundException:
                logger().debug(
                    "Ignoring repository %s without a repository policy", repository_arn
                )
                continue

            yield Resource(
                ResourceType.ECR_REPOSITORY,
                repository_arn,
                [Policy(PolicyType.RESOURCE_POLICY, "RepositoryPolicy", policy)],
            )


def validate_resources(resources: Iterable[Resource]):
    """Validate policies of given AWS resources."""
    for resource in resources:
        logger().info(
            "Validating policies of %s %s",
            resource.resource_type.value,
            resource.resource_arn,
        )

        validate_policies(resource)


def validate_policies(resource: Resource):
    """Validate given policies with Access Analyzer"""
    client = boto3.client("accessanalyzer")

    for policy in resource.policies:
        logger().info(
            "Validating policy %s (%s)",
            policy.policy_name,
            policy.policy_type.value,
        )

        kwargs = pydash.omit_by(
            {
                "policyType": policy.policy_type.value,
                "policyDocument": policy.doc,
                "validatePolicyResourceType": resource.validate_policy_resource_type,
            },
            lambda v: v is None,
        )
        for page in client.get_paginator("validate_policy").paginate(**kwargs):
            for finding in page["findings"]:
                policy.add_finding(
                    Finding(
                        finding["findingType"],
                        finding["findingDetails"],
                        finding["issueCode"],
                        finding["learnMoreLink"],
                    )
                )

        if policy.findings:
            logger().debug(
                "%i findings (%s)",
                policy.num_findings,
                ", ".join(
                    [
                        f"{k}={v}"
                        for k, v in pydash.count_by(
                            f.finding_type for f in policy.findings
                        ).items()
                    ]
                ),
            )
        else:
            logger().debug("No findings")


def generate_report(resources: Iterable[Resource]):
    """Generate report for findings."""

    logger().info("Writing report to %s", getattr(args().output, "name", "<memory>"))

    write_output = functools.partial(print, file=args().output)

    timestamp = (
        datetime.datetime.utcnow().isoformat(timespec="seconds").replace("T", " ")
    )
    write_output(f"# IAM Access Analyzer Policy Analysis Report ({timestamp} UTC)")
    write_output()
    write_output("## Summary")
    write_output("")
    write_output("Findings")

    all_findings = pydash.flatten(p.findings for r in resources for p in r.policies)
    for level, count in pydash.sort_by(
        pydash.count_by(all_findings, lambda f: f.finding_type).items(), 1, reverse=True
    ):
        write_output(f"* {level}: {count}")

    write_output()
    write_output("Analyzed Resources")
    for rtype, count in pydash.sort_by(
        pydash.count_by(resources, lambda r: r.resource_type.value).items(),
        1,
        reverse=True,
    ):
        write_output(f"* {rtype}: {count}")

    write_output()
    write_output("Analyzed Policies")
    resource_policy_types = pydash.flatten(
        f"{r.resource_type.value}, {p.policy_type.value}"
        for r in resources
        for p in r.policies
    )

    for rptype, count in pydash.sort_by(
        pydash.count_by(resource_policy_types).items(), 1, reverse=True
    ):
        write_output(f"* {rptype}: {count}")

    write_output()
    write_output("## Details\n")

    grouped_resources = pydash.group_by(resources, lambda r: r.resource_type.value)
    for rtype, resources_for_type in grouped_resources.items():
        write_output(f"### {rtype}")

        for resource in resources_for_type:
            if not resource.num_findings:
                continue

            write_output(f"* {resource.resource_arn}")
            for policy in resource.policies:
                if not policy.findings:
                    continue

                write_output(f"  * {policy.policy_name} ({policy.policy_type.value})")
                for finding in policy.findings:
                    write_output(
                        f"    * {finding.finding_type}: {finding.finding_details}"
                    )
                write_output()


@functools.lru_cache()
def logger():
    """Get module logger."""
    level = logging.DEBUG if args().verbose > 0 else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    botolevel = logging.DEBUG if args().verbose > 1 else logging.INFO
    logging.getLogger("botocore").setLevel(botolevel)
    logging.getLogger("urllib3").setLevel(botolevel)

    return logging.getLogger("validator")


@functools.lru_cache()
def args() -> argparse.Namespace:
    """Parse arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase log level."
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path where report shall be written to. Will be overwritten.",
        required=True,
        type=argparse.FileType("w"),
    )
    parser.add_argument(
        "-r",
        "--regions",
        help=(
            "Comma separated list of regions to discover policies from "
            "(example: --regions eu-west-1,eu-north-1). Default: All commercial regions."
        ),
        type=str,
    )
    return parser.parse_args()


def main():
    """Entrypoint."""
    resources = pydash.flatten(
        [
            list(get_iam_resources()),
            list(get_s3_resources()),
            list(get_sqs_resources()),
            list(get_sns_resources()),
            list(get_ecr_resources()),
        ]
    )
    logger().info(
        "Got %i resources with %i policies",
        len(resources),
        sum(len(r.policies) for r in resources),
    )

    validate_resources(resources)
    generate_report(resources)


if __name__ == "__main__":  # pragma: noqa
    main()
