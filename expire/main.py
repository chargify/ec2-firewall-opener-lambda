import boto3, import time, import json, import os
ec2_client = boto3.client('ec2')
cutoff_days = 3

def handle(event, context):
  sg_group = os.environ['security_group_id']
  response = ec2_client.describe_security_groups(GroupIds=[sg_group])
  cutoff = int(time.time()) - (86400 * cutoff_days)

  for entry in response['SecurityGroups'][0]['IpPermissions'][0]['IpRanges']:
    try:
      createdat = int(entry['Description'].split(' ')[1])
      if(createdat < cutoff):
        revoke_ip(entry['CidrIp'])
  return None

def revoke_ip(cidr):
  ec2_client.revoke_security_group_ingress(
    GroupId=sg_group,
    IpPermissions=[ { 'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp', 'IpRanges': [ { 'CidrIp': cidr } ] } ]
  )
