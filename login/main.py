import boto3, json, sys, time, os, traceback
from oauth2client.client import OAuth2WebServerFlow
from botocore.exceptions import ClientError

flow = OAuth2WebServerFlow(client_id=os.environ['google_client_id'],
  client_secret=os.environ['google_client_secret'],
  scope='email',
  redirect_uri=os.environ['google_redirect_uri'],
  hd=os.environ['domain'])

welcome_html = '<a href="{url}">Login with Google</a>'
def welcome():
  return(welcome_html.format(url=flow.step1_get_authorize_url()))

def add_ip(ip, username):
  sg_group = os.environ['security_group_id']
  ec2_client = boto3.client('ec2')
  cidr = ip + "/32"
  ip_data = { 'CidrIp': cidr,  'Description': username + ' ' + str(int(time.time())) }
  existing = None
  response = ec2_client.describe_security_groups(GroupIds=[sg_group])
  for ip_perm_entry in response['SecurityGroups'][0]['IpPermissions']:
    for entry in ip_perm_entry['IpRanges']:
      if(entry['Description'].split(' ')[0] == username):
        revoke_ip(entry['CidrIp'])
      elif(entry['CidrIp'] == cidr):
        existing = entry
  if not existing:
    ec2_client.authorize_security_group_ingress(
      GroupId=sg_group,
      IpPermissions=ip_perms = [ { 'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp', 'IpRanges': [ ip_data ] } ]
    )

def revoke_ip(cidr):
  ec2_client.revoke_security_group_ingress(
    GroupId=sg_group,
    IpPermissions=[ { 'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'tcp', 'IpRanges': [ { 'CidrIp': cidr } ] } ]
  )

def login(code, ip):
  credentials = flow.step2_exchange(code)
  if credentials.id_token and credentials.id_token.get('hd') == os.environ['domain']:
    username = credentials.id_token['email'].split('@')[0]
    add_ip(ip, username)
    return('Logged in!)
  else:
    return('Access denied!')

def handle(event, context):
  if not event.get("pathParameters"):
    content = welcome()
  elif event["pathParameters"]["proxy"] == "login" and event.get("queryStringParameters") and event.get('requestContext'):
    content = login(event["queryStringParameters"]["code"], event['requestContext']['identity']['sourceIp'])
  else:
    content = "Something went wrong."
  return { "statusCode": 200, "body": content }

  