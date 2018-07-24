import datetime
import logging
import boto3

from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

def is_an_ssm_instance(instance_id):
    filters = [
        {'Name': 'tag:ssm_agent', 'Values': ['true', 'True']}
    ]
    try:
        ec2 = boto3.client('ec2')
        instance = ec2.describe_instances(InstanceIds=[str(instance_id)], Filters=filters)
    except ClientError as err:
        LOGGER.error(str(err))
        return False

    if instance:
        return True
    else:
        LOGGER.error("Error: {0} is not an ssm instance".format(str(instance_id))
        return False

def check_ssm_available(instance_id):
    try:
        ssm = boto3.client('ssm')
    except ClientError as err:
        LOGGER.error("Error: Run Command Failed\n%s", str(err))
        return False

    instance_available = ssm.describe_instance_information()

    if instance_available:
        return True
    else:
        LOGGER.error(str(instance_id) + "Not available, waiting..")
        ec2_wait_ok(instance_id)

def ec2_wait_ok(instance_id):
    try:
        ec2 = boto3.client('ec2')
    except ClientError as err:
        LOGGER.error(str(err))
        return False
    log_event('Waiting for OK state...')

    ec2.get_waiter('instance_status_ok').wait(
        InstanceIds=[instance_id]
    )

    log_event('State OK')

def send_run_command(instance_id, commands):
    try:
        ssm = boto3.client('ssm')
    except ClientError as err:
        LOGGER.error("Error: Run Command Failed\n%s", str(err))
        return False

    try:
        ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='ssm_add_ssh_user_iam',
            TimeoutSeconds=900,
            Parameters={
                'sshUser': '<USERNAME>'
            }
        )
        return True
    except ClientError as err:
        if 'ThrottlingException' in str(err):
            LOGGER.info("RunCommand throttled, automatically retrying...")
            send_run_command(instance_id, commands)
        else:
            LOGGER.error("Error: Run Command Failed\n%s", str(err))
            return False

def log_event(event):
    LOGGER.info(event)

def get_instance_id(event):
    try:
        return str(event['detail']['instance-id'])
    except (TypeError, KeyError) as err:
        LOGGER.error(err)
        return False

def resources_exist(instance_id):
    if not instance_id:
        LOGGER.error('Error: Unable to retrieve Instance ID')
        return False
    else: return True

def lambda_handler(event, _context):
    log_event(event)
    instance_id = get_instance_id(event)
    log_event(instance_id)
    #if is_an_ssm_instance(instance_id):
    if resources_exist(instance_id):
        log_event('Run Command')
        send_run_command(instance_id, commands)
        LOGGER.info('Success')
        return True
    else: return False
