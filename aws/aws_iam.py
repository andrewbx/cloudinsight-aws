#!/usr/bin/env python
import sys, boto3, threading, argparse, requests, logging, time, datetime, json

from botocore.exceptions import ClientError
from Crypto.PublicKey import RSA
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Globals
LOG = logging.getLogger("log.eb_aws_iam")

# Hide annoying log messages
logging.getLogger(
    "botocore.vendored.requests.packages.urllib3.connectionpool"
).setLevel(logging.WARNING)
logging.getLogger(
    "botocore"
).setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="IAM - SSH Public/Private key pair management.",
        epilog="""Note:
	    This will delete any existing keys and create a new key."""
    )
    parser.add_argument(
        "-u",
	"--username",
	required=True,
	metavar="username",
	help="IAM Account User name"
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

    username = args.username

    LOG.info(
        "Generating new SSH Public/Private key pair {0} and storing SSH Public Key in IAM".format(
            username
        )
    )
    payload = aws_iam_create_key()
    aws_iam_delete_key(username)
    aws_iam_upload_key(username, payload)
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
            SSHPublicKeyBody=payload.publickey().exportKey("OpenSSH")
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

if __name__ == "__main__":
    main()
