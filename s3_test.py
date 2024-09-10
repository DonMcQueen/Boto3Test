import boto3
import requests
import json

# Create a client
s3_client = boto3.client('s3')

s3response = s3_client.list_buckets()

print('Existing buckets:')
for bucket in s3response['Buckets']:
    print(f'  {bucket["Name"]}')
# x = ec2response['Reservations'][0]['Instances'][0]['InstanceId']
# y = ec2response['Reservations'][0]['Instances'][0]['InstanceType']
# z = ec2response['Reservations'][0]['Instances'][0]['KeyName']
# w = ec2response['Reservations'][0]['Instances'][0]['ImageId']

# response_json = json.loads(response.text)

# print(x)
# print(w)
# print(y)
# print(z)