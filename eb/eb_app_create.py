#!/usr/bin/env python
import os, sys, boto3, threading, argparse, logging, requests, time, datetime, json

from lib import CIClient
from botocore.exceptions import ClientError
from Crypto.PublicKey import RSA
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Globals
EB = boto3.client("elasticbeanstalk")
S3 = boto3.client("s3")
LOG = logging.getLogger("log.eb_app_create")

# Hide annoying log messages
logging.getLogger(
    "botocore.vendored.requests.packages.urllib3.connectionpool"
).setLevel(logging.WARNING)
logging.getLogger(
    "botocore"
).setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# AWS Secret Manager
region = "us-west-2"
region_name = region
endpoint_url = "https://secretsmanager.%s.amazonaws.com" % (region)
kms_arn = "<KMS_ARN>"
user_name = "<USERNAME>"

# EB Configuration
solution_stack = "64bit Amazon Linux 2018.03 v3.0.1 running Tomcat 8.5 Java 8"
eb_ec2key = "<EC2KEY>"
eb_subnet = "<SUBNET>"
eb_sg = "<SECURITYGROUP>"
option_settings = []

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Get AWS Secret Manager Credentials, Update Cloud Insight/AWS EB Environment.",
        epilog="""Known limitation:
            Single instance environments may report a failure if a \'Rolling' deployment is used.
            This is due to the environment health not remaining green when there are 0 active instances.
            The workaround is to use a \'Rolling with additional batch\' deployment to keep the environment green.""",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=True,
	metavar="username",
        help="User name / email address for Insight API Authentication",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
	metavar="password",
        help="Password for Insight API Authentication",
    )
    parser.add_argument(
        "-d",
        "--dc",
        required=True,
	metavar="dc",
        help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport",
    )
    parser.add_argument(
        "-c",
        "--cid",
        required=True,
	metavar="cid",
        help="Target Alert Logic Customer ID for processing",
    )
    parser.add_argument(
        "-e",
        "--eid",
        required=True,
	metavar="eid",
        help="Target Alert Logic Cloud Insight Environment ID for processing",
    )
    parser.add_argument(
        "-v",
	"--vpc",
	required=True,
	metavar="vpc",
	help="Target Alert Logic VPC ID for updating"
    )
    parser.add_argument(
        "-a",
        "--application-name",
        required=False,
	metavar="application_name",
        help="The EB application which owns the target environment",
    )
    parser.add_argument(
        "-n",
        "--environment-name",
        required=False,
	metavar="environment_name",
        help="The EB environment which should be updated",
    )
    parser.add_argument(
        "-l",
        "--version-label",
        required=False,
	metavar="version_label",
        help="The EB application version which should be applied to the environment",
    )
    parser.add_argument(
        "-b",
        "--s3-bucket",
        required=True,
	metavar="s3_bucket",
        help="The S3 bucket to store the software package into",
    )
    parser.add_argument(
        "-f",
        "--package-file",
        required=True,
	metavar="package_file",
        help="The local software package file to publish",
    )
    parser.add_argument(
        "--log",
        dest="loglevel",
        choices=['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'],
        metavar="log",
        help="Logging level, set to DEBUG, WARNING, ERROR, CRITICAL (Default=INFO)",
        default="INFO"
    )

    try:
        args = parser.parse_args()
    except:
        sys.exit(1)

    if args.loglevel:
        logging.basicConfig(
            format="%(asctime)s %(name)s %(levelname)s - %(message)s", level=logging.getLevelName(args.loglevel)
        )

    ci_args = {}

    if args.dc == "defender-us-denver":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-us-ashburn":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.com"
    elif args.dc == "defender-uk-newport":
        ci_args["yarp"] = "api.cloudinsight.alertlogic.co.uk"

    ci_args["user"] = args.username
    ci_args["password"] = args.password
    ci_args["acc_id"] = args.cid
    ci_args["env_id"] = args.eid
    ci_args["log_level"] = args.loglevel

    vpc_id = args.vpc

    LOG.info("Load secret {0} from AWS Secret Manager".format(vpc_id))
    keys = json.loads(
        awssm_get_secret(
            secret_name=vpc_id, endpoint_url=endpoint_url, region_name=region_name
        )
    )

    perform_ci_update(ci_args, keys, region, vpc_id)

    if args.application_name and args.environment_name and args.version_label:
        perform_environment_create(
            args.application_name,
            args.environment_name,
            args.version_label,
            keys,
            args.s3_bucket,
            args.package_file,
            vpc_id,
        )
    return


# -----------------------------------------------------------------------------
# AWS Secret Manager functions.
# -----------------------------------------------------------------------------
def awssm_get_secret(secret_name, endpoint_url, region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name,
        endpoint_url=endpoint_url,
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            LOG.error("The requested secret " + secret_name + " was not found")
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            LOG.error("The request was invalid due to:", e)
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            LOG.error("The request had invalid params:", e)
    else:
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
            return secret
        else:
            binary_secret_data = get_secret_value_response["SecretBinary"]
            return binary_secret_data


def awssm_create_secret():
    key = RSA.generate(2048)
    LOG.info("Private:\n{0}".format(key.exportKey("PEM")))

    pubkey = key.publickey()
    LOG.info("Public:\n{0}".format(pubkey.exportKey("OpenSSH")))

    return key


def awssm_store_secret(
    secret_name, endpoint_url, region_name, kms_arn, vpc_id, payload, user_name
):
    ssh_payload = {}
    ssh_payload["vpc_id"] = vpc_id
    ssh_payload["private"] = payload.exportKey("PEM")
    ssh_payload["public"] = payload.publickey().exportKey("OpenSSH")
    ssh_payload["user"] = user_name
    ssh_payload["version"] = str(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"))

    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name,
        endpoint_url=endpoint_url,
    )
    try:
        create_secret_response = client.create_secret(
            Name=secret_name, KmsKeyId=kms_arn, SecretString=json.dumps(ssh_payload)
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            LOG.error("Secret with name {0} already exists".format(secret_name))
        else:
            LOG.error("Error: {0}".format(e.response))
    else:
        LOG.info("Secret created {0}".format(create_secret_response["ARN"]))
        return create_secret_response


def awssm_update_secret(
    secret_name, endpoint_url, region_name, kms_arn, vpc_id, payload, user_name
):
    ssh_payload = {}
    ssh_payload["vpc_id"] = vpc_id
    ssh_payload["private"] = payload.exportKey("PEM")
    ssh_payload["public"] = payload.publickey().exportKey("OpenSSH")
    ssh_payload["user"] = user_name
    ssh_payload["version"] = str(datetime.datetime.now().strftime("%Y-%m-%d_%H:%M"))

    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager",
        region_name=region_name,
        endpoint_url=endpoint_url,
    )
    try:
        update_secret_response = client.update_secret(
            SecretId=secret_name, KmsKeyId=kms_arn, SecretString=json.dumps(ssh_payload)
        )
    except ClientError as e:
        LOG.error("Error: {0}".format(e.response))
        return False
    else:
        LOG.info(
            "Secret updated {0} version {1}".format(
                update_secret_response["ARN"], update_secret_response["VersionId"]
            )
        )
        return update_secret_response


# -----------------------------------------------------------------------------
# Cloud Insight
# -----------------------------------------------------------------------------
def ci_register_secret(
    ci_client,
    secret_name,
    asset_type,
    asset_key,
    payload,
    user_name,
    cred_type,
    cred_sub_type,
):
    cred_payload = {}
    cred_payload["name"] = secret_name
    cred_payload["type"] = cred_type
    cred_payload["sub_type"] = cred_sub_type
    cred_payload["username"] = user_name
    cred_payload["key"] = str(payload["private"])
    response = ci_client.create_scan_credentials(
        asset_type=asset_type, asset_key=asset_key, payload=json.dumps(cred_payload)
    )
    return response


def perform_ci_update(ci_args, keys, region, vpc):
    LOG.info(
        "Insert private key from AWS Secret Manager to Cloud Insight in VPC: {0}".format(
            vpc
        )
    )
    myCI = CIClient.CloudInsight(ci_args)
    asset_type = "vpc"
    asset_key = "/aws/{}/vpc/{}".format(region, vpc)
    cred_type = "ssh"
    cred_sub_type = "key"
    ci_secret_response = ci_register_secret(
        ci_client=myCI,
        secret_name=vpc,
        asset_type=asset_type,
        asset_key=asset_key,
        payload=keys,
        user_name=user_name,
        cred_type=cred_type,
        cred_sub_type=cred_sub_type,
    )
    if ci_secret_response:
        LOG.info("Success: {0}".format(ci_secret_response))
    else:
        LOG.error("Error: {0}".format(ci_secret_response))
    return


# -----------------------------------------------------------------------------
# Update the specified environment to the specified version
# Wait for the update to complete and log environment events
# Wait to ensure the environment stays healthy for a time period
# -----------------------------------------------------------------------------
def perform_environment_create(
    application, environment, version, keys, bucket, package, vpc_id
):
    LOG.info("Creating environment %s version %s", environment, version)

    eb_option = {}
    eb_option["OptionName"] = "SSH_KEY"
    eb_option["Namespace"] = "aws:elasticbeanstalk:application:environment"
    eb_option["Value"] = str(keys["public"]).replace("\\n", "\n")
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "Subnets"
    eb_option["Namespace"] = "aws:ec2:vpc"
    eb_option["Value"] = eb_subnet
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "ELBSubnets"
    eb_option["Namespace"] = "aws:ec2:vpc"
    eb_option["Value"] = eb_subnet
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "AssociatePublicIpAddress"
    eb_option["ResourceName"] = "AWSEBAutoScalingLaunchConfiguration"
    eb_option["Namespace"] = "aws:ec2:vpc"
    eb_option["Value"] = "true"
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "ELBScheme"
    eb_option["Namespace"] = "aws:ec2:vpc"
    eb_option["Value"] = "public"
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "VPCid"
    eb_option["Namespace"] = "aws:ec2:vpc"
    eb_option["Value"] = vpc_id
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "SecurityGroups"
    eb_option["ResourceName"] = "AWSEBAutoScalingLaunchConfiguration"
    eb_option["Namespace"] = "aws:autoscaling:launchconfiguration"
    eb_option["Value"] = eb_sg
    option_settings.append(eb_option)

    eb_option = {}
    eb_option["OptionName"] = "EC2KeyName"
    eb_option["ResourceName"] = "AWSEBAutoScalingLaunchConfiguration"
    eb_option["Namespace"] = "aws:autoscaling:launchconfiguration"
    eb_option["Value"] = eb_ec2key
    option_settings.append(eb_option)

    template_name = "cfg_{0}".format(str(application))

    if not os.path.isfile(package):
        LOG.error("Cannot locate package: %s", package)
        sys.exit(1)

    create_application(application)
    create_config_template(application, template_name, solution_stack, option_settings)
    publish_app_version(application, version, bucket, package)

    environment_id, request_id = create_environment(
        application, environment, template_name, option_settings
    )
    LOG.info("Creation has been requested: %s", request_id)

    logged_events = []

    wait_for_ready_status(environment_id, request_id, logged_events)
    LOG.info("Environment creation has been completed")

    environment_id, request_id = update_environment_to_version(
        application, environment, version, option_settings
    )
    LOG.info("Update has been requested: %s", request_id)

    logged_events = []

    wait_for_ready_status(environment_id, request_id, logged_events)
    LOG.info("Environment update has been completed")

    duration = 60
    LOG.info("Monitor environment health for %d seconds", duration)

    result = monitor_env_health(
        environment_id, version, duration, request_id, logged_events
    )
    if not result:
        LOG.error("Release Failed!")
        sys.exit(1)
    else:
        LOG.info("Release Complete!")
    return


# -----------------------------------------------------------------------------
# Publish a new application version
# Upload the specified package to S3
# Create the new application version within Elastic Beanstalk
# -----------------------------------------------------------------------------
def publish_app_version(application, version, bucket, package):

    LOG.info("Publishing version %s for '%s'", version, application)

    LOG.info("Uploading %s to s3://%s", package, bucket)
    s3_key = upload_package(package, bucket)
    LOG.info("Package %s has been uploaded to s3://%s", package, bucket)

    create_app_version(application, version, bucket, s3_key)
    LOG.info("Application %s version %s created successfully", application, version)

    LOG.info("Publish Complete!")
    return


# -----------------------------------------------------------------------------
# Upload package to S3 bucket (with unique name)
# -----------------------------------------------------------------------------
def upload_package(package, bucket):
    # Ensure S3 key (filename) is unique
    filename = os.path.split(package)[1]  # remove preceeding path if any
    filename, extension = os.path.splitext(filename)
    key = "{0}-{1}{2}".format(filename, int(time.time()), extension)

    S3.upload_file(package, bucket, key)
    return key


# -----------------------------------------------------------------------------
# Create new application version
# -----------------------------------------------------------------------------
def create_app_version(application, version, bucket, key):

    description = "{0} published at {1}".format(
        version, time.strftime("%d-%b-%Y %H:%M:%S")
    )

    response = EB.create_application_version(
        ApplicationName=application,
        VersionLabel=version,
	Description=description,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        AutoCreateApplication=False,
        Process=True,
    )
    return


# -----------------------------------------------------------------------------
# Update Environment to the Specified Version
# -----------------------------------------------------------------------------
def update_environment_to_version(application, environment, version, option_settings):
    response = EB.update_environment(
        ApplicationName=application,
        EnvironmentName=environment,
        VersionLabel=version,
        OptionSettings=option_settings,
    )
    LOG.debug(response)

    environment_id = response["EnvironmentId"]
    request_id = response["ResponseMetadata"]["RequestId"]
    return (environment_id, request_id)


# -----------------------------------------------------------------------------
# Create Environment
# -----------------------------------------------------------------------------
def create_environment(application, environment, template_name, option_settingss):
    response = EB.create_environment(
        ApplicationName=application,
        EnvironmentName=environment,
        CNAMEPrefix=environment,
        Tier={"Name": "WebServer", "Type": "Standard"},
        Tags=[{"Key": "name", "Value": environment}],
        TemplateName=template_name,
    )
    LOG.debug(response)

    environment_id = response["EnvironmentId"]
    request_id = response["ResponseMetadata"]["RequestId"]
    return (environment_id, request_id)


def create_application(application):
    response = EB.describe_applications(ApplicationNames=[application])
    if (
        not response["Applications"]
        or response["Applications"][0]["ApplicationName"] != application
    ):
        response = EB.create_application(ApplicationName=application, Description="")
        LOG.info("Elastic Application created: {0}".format(application))
        return True
    else:
        LOG.info("Elastic Application already exists: {0}".format(application))
        return False


def create_config_template(application, template_name, solution_stack, option_settings):
    response = EB.describe_applications(ApplicationNames=[application])
    if not template_name in response["Applications"][0]["ConfigurationTemplates"]:
        response = EB.create_configuration_template(
            ApplicationName=application,
            TemplateName=template_name,
            SolutionStackName=solution_stack,
            OptionSettings=option_settings,
        )
        LOG.info("Elastic Config template created: {0}".format(application))
        return True
    else:
        LOG.info("Elastic Config template already exists: {0}".format(application))
        return False


# -----------------------------------------------------------------------------
# Get Environment Details
# -----------------------------------------------------------------------------
def get_env_details(environment_id):
    response = EB.describe_environments(
        EnvironmentIds=[environment_id], IncludeDeleted=False
    )
    details = response["Environments"][0]
    return details


def get_env_status(environment_id):
    details = get_env_details(environment_id)
    status = details["Status"]
    return status


def get_env_health(environment_id):
    details = get_env_details(environment_id)
    health = details["Health"]
    return health


# -----------------------------------------------------------------------------
# Wait for environment to reach 'Ready' status
# 'Ready' means the environment update has completed
# -----------------------------------------------------------------------------
def wait_for_ready_status(environment_id, request_id, logged_events):

    while 1:
        # Log environment update events while we wait for Ready status
        log_new_events(request_id, logged_events)

        current_status = get_env_status(environment_id)
        LOG.debug("Current environment status is %s", current_status)

        if current_status == "Ready":
            LOG.info("Environment status transition to 'Ready' completed")
            break
        else:
            time.sleep(15)
    return


# -----------------------------------------------------------------------------
# Log events which have not been logged before
# -----------------------------------------------------------------------------
def log_new_events(request_id, logged_events):
    response = EB.describe_events(RequestId=request_id, Severity="INFO")
    events = response["Events"]  # Note, events come newest first

    for event in reversed(events):
        if event in logged_events:
            continue

        LOG.info(
            "... %s [%s] %s",
            event["EventDate"].strftime("%H:%M:%S"),
            event["Severity"],
            event["Message"],
        )
        logged_events.append(event)
    return


# -----------------------------------------------------------------------------
# Check that the release was successful
# Checks version is correct and then monitors health for a time period
# -----------------------------------------------------------------------------
def monitor_env_health(environment_id, version, duration, request_id, logged_events):
    cutoff = time.time() + duration

    result = check_env_version(
        environment_id, version, cutoff, request_id, logged_events
    )
    if not result:
        return

    result = ensure_env_health_green(environment_id, cutoff, request_id, logged_events)
    return result


# -----------------------------------------------------------------------------
# Check environment version is the one we expected
# It may be different if EB automatically rolled back a failed update
# -----------------------------------------------------------------------------
def check_env_version(environment_id, version, cutoff, request_id, logged_events):

    # Wait for health to be non-grey before checking version
    while True:
        # Log new events while we wait
        log_new_events(request_id, logged_events)

        details = get_env_details(environment_id)
        current_health = details["Health"]
        if current_health != "Grey":
            LOG.debug("Have reached a non-grey health (%s)", current_health)

            current_version = details["VersionLabel"]
            if current_version != version:
                LOG.error(
                    "Version after upgrade did not match expected version (%s)",
                    current_version,
                )
                return False
            else:
                return True

        if time.time() > cutoff:
            LOG.error("Failed to reach non-grey health before cutoff")
            return False
        else:
            time.sleep(15)
    return


# -----------------------------------------------------------------------------
# Monitor environment health for the specified duration
# This helps to ensure the new version doesn't fail soon after deployment
# -----------------------------------------------------------------------------
def ensure_env_health_green(environment_id, cutoff, request_id, logged_events):

    while True:
        # Log new events while we wait (should be none unless something goes wrong)
        log_new_events(request_id, logged_events)

        health = get_env_health(environment_id)
        if health != "Green":
            LOG.error("Environment health is not 'Green' after update (%s)", health)
            return False

        LOG.info("... Environment health is Green")

        if time.time() > cutoff:
            break
        else:
            time.sleep(15)

    LOG.info("Monitoring complete. Environment is healthy")
    return True


if __name__ == "__main__":
    main()
