import boto3
import logging
from botocore.exceptions import ClientError

sg = '<SECURITY GROUP ID>'

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

def log_event(event):
    LOGGER.info(event)

def get_instance_id(event):
    try:
        return str(event['detail']['instance-id'])
    except (TypeError, KeyError) as err:
        LOGGER.error(err)
        return False

def update_sg(instance_id):
    try:
        ec2 = boto3.client('ec2')
    except ClientError as err:
        LOGGER.error(str(err))
        return False

    response = ec2.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='groupSet'
    )

    sg_array = list()

    for r in response['Groups']:
        sg_array.append(r['GroupId'])

    sg_array.append(sg)
    log_event(sg_array)

    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=sg_array
    )

def lambda_handler(event, _context):
    log_event(event)
    instance_id = get_instance_id(event)
    update_sg(instance_id)
