# 🛠️ CloudPatch

CloudPatch is a CLI-based AWS security hardening tool built for **blue teams**, **DevSecOps pipelines**, and **pre-deployment audit workflows**. It scans for misconfigurations across core AWS services and optionally remediates issues — with support for multi-account AWS orgs and GPT-4 summaries.



## 🔍 What It Does

✅ **EC2 Instance Audits**: Flag outdated AMIs (>90 days), suggest rebuilds
✅ **VPC Check**: Detect and optionally delete default VPCs
✅ **EBS Volume Scan**: Detect unencrypted volumes
✅ **RDS Audit**: Flag unencrypted RDS instances
✅ **Lambda Review**: Identify environment variables that may leak secrets
🤖 **GPT Summary**: Uses ChatGPT to summarize and suggest actions
🌐 **Multi-Account Support**: Scan across your AWS Org using assumed roles
🔧 **Remediation Mode**: Use `--remediate` flag to take corrective action



## 🚀 How to Run

### 1. Install Dependencies

```bash
pip install boto3 openai python-dotenv

python cloudpatch_cli.py --region us-east-1 --check all --gpt-summary
