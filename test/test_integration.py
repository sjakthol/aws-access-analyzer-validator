from datetime import datetime
import logging
import pathlib
import sys
import uuid

import boto3
import pytest

import aa_validator

WAITER_CONFIG = {"Delay": 5, "MaxAttempts": 60}


@pytest.fixture(scope="session", autouse=True)
def test_resources():
    template_body = (
        pathlib.Path(__file__).parent / "templates" / "test-resources.yaml"
    ).read_text()

    run_id = str(int(datetime.now().timestamp())) + str(uuid.uuid4()).split("-")[0]
    stack_name = f"aws-access-analyzer-validator-integration-test-{run_id}"

    client_ew1 = boto3.client("cloudformation", region_name="eu-west-1")
    client_en1 = boto3.client("cloudformation", region_name="eu-north-1")
    try:
        client_ew1.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_IAM"],
        )

        client_en1.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_IAM"],
        )
    except:
        pytest.skip("Failed to setup test resources, skipping integration tests.")
        return

    logging.info("Waiting for resources to be ready...")
    client_ew1.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig=WAITER_CONFIG
    )
    client_en1.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig=WAITER_CONFIG
    )

    logging.info("Resources ready. Running tests...")
    yield

    logging.info("Deleting resources")

    client_ew1.delete_stack(StackName=stack_name)
    client_en1.delete_stack(StackName=stack_name)

    logging.info("Waiting for deletion to complete.")
    client_ew1.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig=WAITER_CONFIG
    )
    client_en1.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig=WAITER_CONFIG
    )


def test_integration(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["aws-access-analyzer-validator", "--output", "-"])

    aa_validator.args.cache_clear()
    aa_validator.get_regions.cache_clear()
    aa_validator.main()

    report = capsys.readouterr().out

    assert "* arn:aws:iam::" in report
    assert "* arn:aws:s3::" in report
    assert "* arn:aws:sns:eu-north-1:" in report
    assert "* arn:aws:sns:eu-west-1:" in report
    assert "* arn:aws:ecr:eu-north-1:" in report

    assert "* ERROR" in report
    assert "* SECURITY_WARNING" in report
    assert "* WARNING" in report


def test_integration_regions(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aws-access-analyzer-validator",
            "--output",
            "-",
            "--regions",
            "eu-north-1,us-east-1",
        ],
    )

    aa_validator.args.cache_clear()
    aa_validator.get_regions.cache_clear()
    aa_validator.main()

    report = capsys.readouterr().out

    # eu-west-1 had some problems but --regions flag should've made
    # validator ignore that region
    assert ":eu-west-1:" not in report
