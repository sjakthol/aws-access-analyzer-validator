# IAM Access Analyzer Policy Analysis Report (2021-08-28 17:58:53 UTC)

## Summary

Findings
* ERROR: 18
* SUGGESTION: 13
* SECURITY_WARNING: 13
* WARNING: 1

Analyzed Resources
* AWS::IAM::Role: 21
* AWS::IAM::User: 6
* AWS::IAM::Group: 6
* AWS::IAM::Policy: 6
* AWS::SNS::Topic: 6
* AWS::S3::Bucket: 4

Analyzed Policies
* AWS::IAM::Role, RESOURCE_POLICY: 21
* AWS::IAM::Role, IDENTITY_POLICY: 10
* AWS::IAM::User, IDENTITY_POLICY: 8
* AWS::IAM::Group, IDENTITY_POLICY: 8
* AWS::IAM::Policy, IDENTITY_POLICY: 6
* AWS::SNS::Topic, RESOURCE_POLICY: 6
* AWS::S3::Bucket, RESOURCE_POLICY: 4

## Details

### AWS::IAM::User
* arn:aws:iam::012345678901:user/en1-aa-validator-test-resources-User3-1OOFHZNC0QTMB
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:iam::012345678901:user/ew1-aa-validator-test-resources-User3-BM8TCG6S7A3Q
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

### AWS::IAM::Group
* arn:aws:iam::012345678901:group/en1-aa-validator-test-resources-Group3-1V7D2KH8WU9CP
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:iam::012345678901:group/ew1-aa-validator-test-resources-Group3-DS7GASDPFSF9
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

### AWS::IAM::Role
* arn:aws:iam::012345678901:role/aws-ec2-spot-fleet-tagging-role
  * AssumeRolePolicyDocument (RESOURCE_POLICY)
    * SUGGESTION: Add a value to the empty string in the Sid element.

* arn:aws:iam::012345678901:role/en1-aa-validator-test-resources-Role3-1X2TN1FNDCDHF
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:iam::012345678901:role/en1-aa-validator-test-resources-Role4-1WOLIE3Z3LRCG
  * AssumeRolePolicyDocument (RESOURCE_POLICY)
    * SUGGESTION: Add a value to the empty string in the Sid element.

* arn:aws:iam::012345678901:role/ew1-aa-validator-test-resources-Role3-1NWKI4TCDU06B
  * InvalidInlinePolicy (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

  * InvalidInlinePolicy2 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:iam::012345678901:role/ew1-aa-validator-test-resources-Role4-G1SVFATA89UL
  * AssumeRolePolicyDocument (RESOURCE_POLICY)
    * SUGGESTION: Add a value to the empty string in the Sid element.

* arn:aws:iam::012345678901:role/OrganizationAccountAccessRole
  * AdministratorAccess (IDENTITY_POLICY)
    * WARNING: Using wildcards (*) in the action and the resource can allow creation of unintended service-linked roles because it allows iam:CreateServiceLinkedRole permissions on all resources. We recommend that you specify resource ARNs instead.
    * SECURITY_WARNING: Using wildcards (*) in the action and the resource can be overly permissive because it allows iam:PassRole permissions on all resources. We recommend that you specify resource ARNs or add the iam:PassedToService condition key to your statement.

### AWS::IAM::Policy
* arn:aws:iam::012345678901:policy/ew1-aa-validator-test-resources-ManagedPolicy3-L1110ZGOTE09
  * ew1-aa-validator-test-resources-ManagedPolicy3-L1110ZGOTE09 (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:iam::012345678901:policy/en1-aa-validator-test-resources-ManagedPolicy2-1S3SIXTP3TJJY
  * en1-aa-validator-test-resources-ManagedPolicy2-1S3SIXTP3TJJY (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

* arn:aws:iam::012345678901:policy/ew1-aa-validator-test-resources-ManagedPolicy2-WF2DOD6MIS6Z
  * ew1-aa-validator-test-resources-ManagedPolicy2-WF2DOD6MIS6Z (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.

* arn:aws:iam::012345678901:policy/en1-aa-validator-test-resources-ManagedPolicy3-1BLGKR4NQK8HJ
  * en1-aa-validator-test-resources-ManagedPolicy3-1BLGKR4NQK8HJ (IDENTITY_POLICY)
    * ERROR: The action ec2:NotAnAction does not exist.
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

### AWS::S3::Bucket
* arn:aws:s3:::en1-aa-validator-test-resources-bucket3-x5di46piqflh
  * BucketPolicy (RESOURCE_POLICY)
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:s3:::ew1-aa-validator-test-resources-bucket3-tz711jv0rtb
  * BucketPolicy (RESOURCE_POLICY)
    * SUGGESTION: The non-zero bits in the IP address after the masked bits are ignored. Replace address with 172.0.0.0.
    * SECURITY_WARNING: Using the condition key aws:VpcSourceIp can be overly permissive without also using the following condition keys: aws:SourceVPC, aws:SourceVPCE. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

### AWS::SNS::Topic
* arn:aws:sns:eu-north-1:012345678901:en1-aa-validator-test-resources-Topic1-9FXS7KJ8KL1P
  * TopicPolicy (RESOURCE_POLICY)
    * ERROR: The action SNS:Receive does not exist.

* arn:aws:sns:eu-north-1:012345678901:en1-aa-validator-test-resources-Topic3-PC7CZ5D252JK
  * TopicPolicy (RESOURCE_POLICY)
    * SECURITY_WARNING: Using the condition key aws:SourceArn can be overly permissive without also using the following condition keys: aws:SourceAccount. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

* arn:aws:sns:eu-west-1:012345678901:ew1-aa-validator-test-resources-Topic1-10G9A1T933X0A
  * TopicPolicy (RESOURCE_POLICY)
    * ERROR: The action SNS:Receive does not exist.

* arn:aws:sns:eu-west-1:012345678901:ew1-aa-validator-test-resources-Topic3-KJSDRZXB935Z
  * TopicPolicy (RESOURCE_POLICY)
    * SECURITY_WARNING: Using the condition key aws:SourceArn can be overly permissive without also using the following condition keys: aws:SourceAccount. Condition keys like this one are more secure when paired with a related key. We recommend that you add the related condition keys to the same condition block.

