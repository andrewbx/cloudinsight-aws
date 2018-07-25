#!/usr/bin/env python
import sys, boto3, threading, argparse, logging, requests, time, datetime, json

from lib import CIClient
from botocore.exceptions import ClientError
from Crypto.PublicKey import RSA
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Globals
EB = boto3.client("elasticbeanstalk")
logging.basicConfig(
    format="%(asctime)s %(name)s %(levelname)s - %(message)s", level=logging.INFO
)
LOG = logging.getLogger("log.iam_ci_update")

# Hide annoying log messages
logging.getLogger(
    "botocore.vendored.requests.packages.urllib3.connectionpool"
).setLevel(logging.WARNING)
logging.getLogger(
    "botocore"
).setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

region = "us-west-2"

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Create SSH Private/Public Key/Update Cloud Insight.",
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
        "-i",
	"--iam",
	required=True,
	metavar="iam",
	help="Target Alert Logic IAM User for updating SSH Key"
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

    username = args.iam
    vpc_id = args.vpc

    LOG.info(
        "Generating new SSH Public/Private key pair {0} and storing SSH Public Key in IAM".format(
            username
        )
    )

    payload = aws_iam_create_key()
    aws_iam_delete_key(username)
    aws_iam_upload_key(username, payload)

    perform_ci_update(ci_args, payload.exportKey('PEM'), region, vpc_id, username)
    return


# -----------------------------------------------------------------------------
# IAM functions.
# -----------------------------------------------------------------------------
def aws_iam_create_key():
    key = RSA.generate(2048)
    LOG.debug("Private Key:\n{0}".format(key.exportKey('PEM')))

    pubkey = key.publickey()
    LOG.debug("Public Key:\n{0}".format(pubkey.exportKey('OpenSSH')))
    return key


def aws_iam_upload_key(
    username, payload
):
    try:
        client = boto3.client('iam')
    except ClientError as err:
        LOG.error(str(err))
        return False

    try:
	response = client.upload_ssh_public_key(
            UserName=username,
            SSHPublicKeyBody=payload.publickey().exportKey('OpenSSH')
        )
    except ClientError as err:
        LOG.error("Error: {0}".format(err.response))
    else:
        LOG.info("Creating SSH Public Key for {0} ({1})".format(username, response['SSHPublicKey']['SSHPublicKeyId']))
        return response


def aws_iam_delete_key(
    username
):
    try:
        client = boto3.client('iam')
    except ClientError as err:
        LOG.error(str(err))
        return False

    try:
        response = client.list_ssh_public_keys(
            UserName=username
        )
    except ClientError as err:
           LOG.error("Error: {0}".format(err.response))
    else:
           for r in response['SSHPublicKeys']:
               LOG.info("Deleting SSH Public Key for {0} ({1})".format(username, r['SSHPublicKeyId']))
               client.delete_ssh_public_key(
                   UserName=username,
                   SSHPublicKeyId=r['SSHPublicKeyId']
               )


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
    cred_payload["key"] = payload
    response = ci_client.create_scan_credentials(
        asset_type=asset_type, asset_key=asset_key, payload=json.dumps(cred_payload)
    )
    return response


def perform_ci_update(ci_args, keys, region, vpc, user_name):
    LOG.info(
        "Insert SSH Generated Private Key to Cloud Insight in VPC: {0}".format(
            vpc
        )
    )
    ci_h = CIClient.CloudInsight(ci_args)
    asset_type = "vpc"
    asset_key = "/aws/{}/vpc/{}".format(region, vpc)
    cred_type = "ssh"
    cred_sub_type = "key"
    ci_secret_response = ci_register_secret(
        ci_client=ci_h,
        secret_name=vpc,
        asset_type=asset_type,
        asset_key=asset_key,
        payload=keys,
        user_name=user_name,
        cred_type=cred_type,
        cred_sub_type=cred_sub_type,
    )
    if ci_secret_response:
        LOG.info("Success: {0}".format(json.dumps(ci_secret_response)))
    else:
        LOG.error("Error: {0}".format(ci_secret_response))
    return


if __name__ == "__main__":
    main()
