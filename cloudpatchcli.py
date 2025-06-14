# cloudpatch_cli.py

import argparse
import boto3
import datetime
import json
import os
from botocore.exceptions import ClientError
from openai import OpenAI


def gpt_summarize_findings(findings):
    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        messages = [
            {"role": "system", "content": "You are a security assistant that summarizes AWS findings and provides remediation suggestions."},
            {"role": "user", "content": f"Summarize the following security findings and suggest actions: {json.dumps(findings)}"}
        ]
        response = client.chat.completions.create(model="gpt-4", messages=messages)
        summary = response.choices[0].message.content
        print("\n[GPT Summary]\n" + summary)
    except Exception as e:
        print(f"[x] GPT Summary failed: {str(e)}")


def check_ec2_instances(region, remediate=False):
    findings = []
    print(f"[+] Checking EC2 instances in {region}...")
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_instances()
    now = datetime.datetime.now(datetime.timezone.utc)
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            launch_time = instance['LaunchTime']
            instance_id = instance['InstanceId']
            age_days = (now - launch_time).days
            if age_days > 90:
                findings.append({"InstanceId": instance_id, "AgeDays": age_days})
                print(f"[!] EC2 Instance {instance_id} is older than 90 days ({age_days} days old)")
                if remediate:
                    print(f"[-] Suggested Action: Replace AMI or rebuild {instance_id}")
            else:
                print(f"[OK] EC2 Instance {instance_id} is within age limit ({age_days} days old)")
    return findings


def check_default_vpcs(region, remediate=False):
    findings = []
    print(f"[+] Checking for default VPCs in {region}...")
    ec2 = boto3.client('ec2', region_name=region)
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        if vpc.get('IsDefault'):
            findings.append({"VpcId": vpc['VpcId'], "Issue": "Default VPC exists"})
            print(f"[!] Default VPC found: {vpc['VpcId']}")
            if remediate:
                try:
                    ec2.delete_vpc(VpcId=vpc['VpcId'])
                    print(f"[-] Deleted default VPC: {vpc['VpcId']}")
                except ClientError as e:
                    print(f"[x] Error deleting VPC {vpc['VpcId']}: {str(e)}")
        else:
            print(f"[OK] Custom VPC: {vpc['VpcId']}")
    return findings


def check_ebs_encryption(region):
    findings = []
    print(f"[+] Checking EBS volumes encryption in {region}...")
    ec2 = boto3.client('ec2', region_name=region)
    volumes = ec2.describe_volumes()['Volumes']
    for vol in volumes:
        if not vol['Encrypted']:
            findings.append({"VolumeId": vol['VolumeId'], "Issue": "Unencrypted"})
            print(f"[!] Unencrypted volume found: {vol['VolumeId']}")
        else:
            print(f"[OK] Encrypted volume: {vol['VolumeId']}")
    return findings


def check_rds_encryption(region):
    findings = []
    print(f"[+] Checking RDS encryption in {region}...")
    rds = boto3.client('rds', region_name=region)
    instances = rds.describe_db_instances()['DBInstances']
    for db in instances:
        if not db.get('StorageEncrypted'):
            findings.append({"DBInstance": db['DBInstanceIdentifier'], "Issue": "Unencrypted"})
            print(f"[!] Unencrypted RDS instance: {db['DBInstanceIdentifier']}")
        else:
            print(f"[OK] Encrypted RDS instance: {db['DBInstanceIdentifier']}")
    return findings


def check_lambda_env_vars(region):
    findings = []
    print(f"[+] Checking Lambda environment variables in {region}...")
    lambda_client = boto3.client('lambda', region_name=region)
    functions = lambda_client.list_functions()['Functions']
    for fn in functions:
        name = fn['FunctionName']
        config = lambda_client.get_function_configuration(FunctionName=name)
        if config.get('Environment') and config['Environment'].get('Variables'):
            findings.append({"Function": name, "Issue": "Environment variables present"})
            print(f"[!] Lambda {name} has environment variables set (check for secrets)")
        else:
            print(f"[OK] Lambda {name} has no environment variables")
    return findings


def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="CloudPatchSession")['Credentials']
    return creds


def main():
    parser = argparse.ArgumentParser(description='CloudPatch CLI - AWS Hardening Tool')
    parser.add_argument('--region', required=True, help='AWS region to scan')
    parser.add_argument('--check', choices=['ec2', 'vpc', 'ebs', 'rds', 'lambda', 'all'], default='all', help='What to check')
    parser.add_argument('--remediate', action='store_true', help='Attempt remediation')
    parser.add_argument('--accounts', nargs='*', help='Comma-separated list of account IDs for org scanning')
    parser.add_argument('--role', default='OrganizationAccountAccessRole', help='IAM Role name to assume')
    parser.add_argument('--gpt-summary', action='store_true', help='Use GPT to summarize findings')

    args = parser.parse_args()
    all_findings = []

    accounts = args.accounts if args.accounts else [None]
    for account in accounts:
        if account:
            creds = assume_role(account, args.role)
            boto3.setup_default_session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            print(f"\n[+] Scanning Account: {account}")

        if args.check in ('ec2', 'all'):
            all_findings.extend(check_ec2_instances(args.region, args.remediate))
        if args.check in ('vpc', 'all'):
            all_findings.extend(check_default_vpcs(args.region, args.remediate))
        if args.check in ('ebs', 'all'):
            all_findings.extend(check_ebs_encryption(args.region))
        if args.check in ('rds', 'all'):
            all_findings.extend(check_rds_encryption(args.region))
        if args.check in ('lambda', 'all'):
            all_findings.extend(check_lambda_env_vars(args.region))

    if args.gpt_summary and all_findings:
        gpt_summarize_findings(all_findings)

if __name__ == '__main__':
    main()
