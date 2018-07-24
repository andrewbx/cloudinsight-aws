#!/usr/bin/env python
import sys, boto3, threading, argparse, requests, logging, time, datetime, json

from botocore.exceptions import ClientError
from Crypto.PublicKey import RSA
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Globals
LOG = logging.getLogger("log.eb_aws_sm")

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

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AWS Secret Manager - SSH Public/Private key pair management.",
        epilog="""Note:
	    If creating a new key in AWS Secret Manager, use action new.
	    Updating existing keys must always be used with replace.""",
    )
    parser.add_argument(
        "-a",
        "--action",
	required=True,
	choices=["new", "replace"],
	metavar="action",
        help="Create new or update existing AWS Secret Manager key. Options: new, or replace"
    )
    parser.add_argument(
        "-v",
	"--vpc",
	required=True,
	metavar="vpc",
	help="Target VPC ID for updating"
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

    vpc_id = args.vpc

    if args.action == "new":
        LOG.info(
            "Generating new SSH Public/Private key pair {0} and storing it in AWS Secret Manager".format(
                vpc_id
            )
        )
        payload = awssm_create_secret()
        awssm_store_secret(
            secret_name=vpc_id,
            endpoint_url=endpoint_url,
            region_name=region_name,
            kms_arn=kms_arn,
            vpc_id=vpc_id,
            payload=payload,
            user_name=user_name,
        )
    elif args.action == "replace":
        LOG.info(
            "Replacing SSH Public/Private key pair for key {0} in AWS Secret Manager".format(
                vpc_id
            )
        )
        payload = awssm_create_secret()
        awssm_update_secret(
            secret_name=vpc_id,
            endpoint_url=endpoint_url,
            region_name=region_name,
            kms_arn=kms_arn,
            vpc_id=vpc_id,
            payload=payload,
            user_name=user_name,
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
    LOG.debug("Private Key:\n{0}".format(key.exportKey('PEM')))

    pubkey = key.publickey()
    LOG.debug("Public Key:\n{0}".format(pubkey.exportKey('OpenSSH')))
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
            LOG.error("Secret with name {0} already exists.".format(secret_name))
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


if __name__ == "__main__":
    main()
