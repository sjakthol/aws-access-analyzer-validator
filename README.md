# aws-access-analyzer-validator

A tool to validate existing identity and resource policies across regions
and supported AWS services with AWS IAM Access Analyzer.

This tool
* discovers resource and identity policies attached to resources of supported
  AWS services (see below) in all commercial regions
* validates these policies with AWS IAM Access Analyzer [ValidatePolicy](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html)
  API
* generates a report with Access Analyzer findings

See [examples/sample_report.md](examples/sample_report.md) for an example.

## Usage

1. Install from PyPI (Python 3.8+ required):

  ```
  pip install aws-access-analyzer-validator
  ```

2. Execute the tool:

  ```
  aws-access-analyzer-validator -o report.md
  ```

3. Open `report.md` to see analysis results.

### Arguments

`aws-access-analyzer-validator` supports the following arguments:

* `--regions` - A comma separated list of regions to limit policy
  validation to. For example, `--regions eu-west-1,eu-north-1` limits
  validation to policies in `eu-west-1` and `eu-north-1` regions. Global
  resources (IAM, S3) are scanned regardless of region limitations.

### Supported Services / Resources

`aws-access-analyzer-validator` validates policies from the following
services:

* AWS Identity and Access Management (IAM)
  * Inline policies of IAM users
  * Inline policies of IAM groups
  * Inline policies and trust policy of IAM roles
  * Managed IAM Policies (customer managed)
* Amazon S3 bucket policies
* Amazon SQS queue policies
* Amazon SNS topic policies
* Amazon Elastic Container Registry (ECR) repository policies

### Required Permissions

This tool requires the following permissions to operate:

* `accessanalyzer:ValidatePolicy`
* `ecr:DescribeRepositories`
* `ecr:GetRepositoryPolicy`
* `iam:GetAccountAuthorizationDetails`
* `s3:GetBucketPolicy`
* `s3:ListAllMyBuckets`
* `sns:GetTopicAttributes`
* `sns:ListTopics`
* `sqs:GetQueueAttributes`
* `sqs:ListQueues`

Here's an IAM policy that grants the required privileges:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PermissionsForAAValidator",
            "Effect": "Allow",
            "Action": [
                "access-analyzer:ValidatePolicy",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "iam:GetAccountAuthorizationDetails",
                "s3:GetBucketPolicy",
                "s3:ListAllMyBuckets",
                "sns:GetTopicAttributes",
                "sns:ListTopics",
                "sqs:GetQueueAttributes",
                "sqs:ListQueues"
            ],
            "Resource": "*"
        }
    ]
}
```

## Development

Requires Python 3.8+ and Poetry. Useful commands:

```bash
# Setup environment
poetry install

# Run integration tests (requires admin-level AWS credentials)
make test

# Run linters
make -k lint

# Format code
make format

# Deploy test resources (requires AWS CLI and admin level AWS credentials)
make deploy-test-resources

# Delete test resources
make delete-test-resources
```

## Credits

* Inspired by [z0ph/aa-policy-validator](https://github.com/z0ph/aa-policy-validator).

## License

MIT.
