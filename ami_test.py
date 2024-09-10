import boto3
import requests
import json

# Create a client
ec2_client = boto3.client('ec2')

response = ec2_client.describe_instances()

x = response['Reservations'][0]['Instances'][0]['InstanceId']
y = response['Reservations'][0]['Instances'][0]['InstanceType']
z = response['Reservations'][0]['Instances'][0]['KeyName']
w = response['Reservations'][0]['Instances'][0]['ImageId']

# response_json = json.loads(response.text)

print(x)
print(w)
print(y)
print(z)