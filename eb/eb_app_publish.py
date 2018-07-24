#!/usr/bin/env python
import sys, boto3, argparse, logging, os.path, time

LOG = logging.getLogger("log.eb_app_publish")

# Hide annoying log messages
logging.getLogger(
    "botocore.vendored.requests.packages.urllib3.connectionpool"
).setLevel(logging.WARNING)
logging.getLogger(
    "botocore"
).setLevel(logging.CRITICAL)

# S3 Hooks
EB = boto3.client("elasticbeanstalk")
S3 = boto3.client("s3")

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main(argv):
    parser = argparse.ArgumentParser(
        description="Publish a new application version to AWS Elastic Beanstalk",
        epilog="""The specified package file should be suitable for the type of
            Elastic Beanstalk application being used. Eg. for Tomcat environments
            this is usually a war file, but could be a zip""",
    )
    parser.add_argument(
        "-a",
        "--application-name",
        required=True,
	metavar="application_name",
        help="The EB application which owns the target environment",
    )
    parser.add_argument(
        "-v",
        "--version-label",
        required=True,
	metavar="version_label",
        help="The name (label) of the new version to create",
    )
    parser.add_argument(
        "-d",
        "--version-description",
        required=False,
	metavar="version_description",
        help="The description of the new version to create",
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

    application = args.application_name
    version = args.version_label
    description = args.version_description
    bucket = args.s3_bucket
    package = args.package_file

    if not os.path.isfile(package):
        LOG.error("Cannot locate package: %s", package)
        sys.exit(1)

    publish_app_version(application, version, description, bucket, package)
    return


# -----------------------------------------------------------------------------
# Publish a new application version
# Upload the specified package to S3
# Create the new application version within Elastic Beanstalk
# -----------------------------------------------------------------------------
def publish_app_version(application, version, description, bucket, package):

    LOG.info("Publishing version %s for '%s'", version, application)

    LOG.info("Uploading %s to s3://%s", package, bucket)
    s3_key = upload_package(package, bucket)
    LOG.info("Package %s has been uploaded to s3://%s", package, bucket)

    create_app_version(application, version, description, bucket, s3_key)
    LOG.info("Application version %s created successfully", version)

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
def create_app_version(application, version, description, bucket, key):

    if description is None:
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


if __name__ == "__main__":
    main(sys.argv)
