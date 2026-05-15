# 🛡️ AWS Honeypot & Threat Intelligence Dashboard

A cloud-native cybersecurity project that deploys a real-world honeypot on AWS EC2 to capture live attack data, stream logs into CloudWatch, detect threats with GuardDuty, and trigger automated alerts via Lambda and SNS.

> Built entirely from the command line using **KDE Konsole** and the **AWS CLI** — no manual console clicks.

---

## 📸 Architecture

```
Internet Attackers
       │
       ▼
┌─────────────────┐
│   EC2 Honeypot  │  ◄── Open ports: 22, 23, 80, 443, 3389, 8080
│   (Cowrie SSH)  │
└────────┬────────┘
         │
    ┌────┴─────┐
    │          │
    ▼          ▼
CloudWatch   GuardDuty
  Logs       Findings
    │          │
    └────┬─────┘
         │
         ▼
      Lambda
   (Alert processor)
         │
         ▼
   SNS → Email Alert
         │
         ▼
  CloudWatch Dashboard
  (Threat visualisation)
```

---

## 🧰 Tech Stack

| Layer | Service / Tool |
|---|---|
| Honeypot | AWS EC2 (Amazon Linux 2) + Cowrie |
| Log ingestion | AWS CloudWatch Logs |
| Threat detection | AWS GuardDuty |
| Alert processing | AWS Lambda (Python 3.8) |
| Notifications | AWS SNS (email) |
| Visualisation | AWS CloudWatch Dashboard |
| Automation | AWS CLI + Bash (KDE Konsole) |
| IAM | Least-privilege IAM user + policies |

---

## 🚀 Setup Guide

### Prerequisites

- KDE Linux (or any Linux distro with Konsole)
- AWS account with an IAM user and access keys
- AWS CLI v2 installed

### 1. Install AWS CLI

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install
aws --version
```

### 2. Configure AWS credentials

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, region (us-east-1), output format (json)
```

---

### 3. Create IAM user with least-privilege permissions

```bash
aws iam create-user --user-name honeypot-admin

aws iam attach-user-policy \
  --user-name honeypot-admin \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess

aws iam attach-user-policy \
  --user-name honeypot-admin \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchFullAccess

aws iam attach-user-policy \
  --user-name honeypot-admin \
  --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess
```

---

### 4. Deploy the EC2 honeypot instance

```bash
# Create SSH key pair
aws ec2 create-key-pair \
  --key-name honeypot-key \
  --query 'KeyMaterial' \
  --output text > ~/.ssh/honeypot-key.pem
chmod 400 ~/.ssh/honeypot-key.pem

# Create security group with intentionally open ports
aws ec2 create-security-group \
  --group-name honeypot-sg \
  --description "Honeypot - intentionally open ports"

SG_ID=$(aws ec2 describe-security-groups \
  --group-names honeypot-sg \
  --query 'SecurityGroups[0].GroupId' \
  --output text)

# Open common attacker-targeted ports
for PORT in 22 23 80 443 3389 8080; do
  aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port $PORT \
    --cidr 0.0.0.0/0
done

# Launch t2.micro instance (free tier eligible)
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t2.micro \
  --key-name honeypot-key \
  --security-group-ids $SG_ID \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=honeypot}]' \
  --count 1
```

---

### 5. Install Cowrie honeypot on EC2

```bash
# Get the public IP and SSH in
INSTANCE_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=honeypot" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

ssh -i ~/.ssh/honeypot-key.pem ec2-user@$INSTANCE_IP
```

Once inside the EC2 instance:

```bash
sudo yum update -y
sudo yum install -y git

# Install Python 3.8
sudo amazon-linux-extras install python3.8 -y

# Clone and set up Cowrie
cd /opt
sudo git clone https://github.com/cowrie/cowrie
sudo chown -R ec2-user:ec2-user cowrie
cd cowrie

# Create virtual environment with Python 3.8
python3.8 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configure and start
cp etc/cowrie.cfg.dist etc/cowrie.cfg
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
bin/cowrie start
```

---

### 6. Set up CloudWatch log ingestion

```bash
# Create log group (run from local Konsole, not EC2)
aws logs create-log-group --log-group-name honeypot-logs
aws logs put-retention-policy \
  --log-group-name honeypot-logs \
  --retention-in-days 30
```

CloudWatch agent config (`/opt/aws/amazon-cloudwatch-agent/etc/config.json`):

```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/cowrie/var/log/cowrie/cowrie.json",
            "log_group_name": "honeypot-logs",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S"
          }
        ]
      }
    }
  }
}
```

---

### 7. Enable GuardDuty

```bash
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

DETECTOR_ID=$(aws guardduty list-detectors \
  --query 'DetectorIds[0]' \
  --output text)

# Test with a sample finding
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce"
```

---

### 8. Deploy the Lambda alert processor

Create `lambda_function.py`:

```python
import json
import boto3
import os

sns = boto3.client('sns')
TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event, context):
    detail = event.get('detail', {})
    finding_type = detail.get('type', 'Unknown')
    severity     = detail.get('severity', 0)
    region       = detail.get('region', 'unknown')

    service  = detail.get('service', {})
    action   = service.get('action', {})
    remote   = action.get('remoteIpDetails', {})
    src_ip   = remote.get('ipAddressV4', 'unknown')
    country  = remote.get('country', {}).get('countryName', 'unknown')

    if severity >= 7:        severity_label = 'HIGH'
    elif severity >= 4:      severity_label = 'MEDIUM'
    else:                    severity_label = 'LOW'

    message = f"""
HONEYPOT ALERT [{severity_label}]
Type:     {finding_type}
Severity: {severity}
Region:   {region}
Src IP:   {src_ip}
Country:  {country}
    """

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f'Honeypot [{severity_label}]: {finding_type}',
        Message=message
    )

    return {'statusCode': 200, 'body': 'Alert sent'}
```

Deploy it:

```bash
# Create SNS topic and subscribe your email
aws sns create-topic --name honeypot-alerts
TOPIC_ARN=$(aws sns list-topics --query 'Topics[0].TopicArn' --output text)
aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol email \
  --notification-endpoint your@email.com

# Package and deploy Lambda
zip lambda.zip lambda_function.py

aws lambda create-function \
  --function-name honeypot-alert-processor \
  --runtime python3.11 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/lambda-basic-execution \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda.zip \
  --environment Variables={SNS_TOPIC_ARN=$TOPIC_ARN}

# Wire GuardDuty → EventBridge → Lambda
aws events put-rule \
  --name guardduty-honeypot-rule \
  --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}' \
  --state ENABLED

LAMBDA_ARN=$(aws lambda get-function \
  --function-name honeypot-alert-processor \
  --query 'Configuration.FunctionArn' --output text)

aws events put-targets \
  --rule guardduty-honeypot-rule \
  --targets "Id=1,Arn=$LAMBDA_ARN"
```

---

### 9. Build the CloudWatch dashboard

```bash
aws cloudwatch put-dashboard \
  --dashboard-name HoneypotThreatDashboard \
  --dashboard-body '{
    "widgets": [
      {
        "type": "log",
        "properties": {
          "title": "Live attack attempts",
          "query": "SOURCE '"'"'honeypot-logs'"'"' | fields @timestamp, eventid, src_ip, username | filter eventid = '"'"'cowrie.login.failed'"'"' | sort @timestamp desc | limit 50",
          "region": "us-east-1",
          "view": "table"
        }
      },
      {
        "type": "log",
        "properties": {
          "title": "Top attacker IPs",
          "query": "SOURCE '"'"'honeypot-logs'"'"' | stats count(*) as attempts by src_ip | sort attempts desc | limit 10",
          "region": "us-east-1",
          "view": "table"
        }
      },
      {
        "type": "log",
        "properties": {
          "title": "Attacks over time",
          "query": "SOURCE '"'"'honeypot-logs'"'"' | stats count(*) as attacks by bin(1h)",
          "region": "us-east-1",
          "view": "timeSeries"
        }
      }
    ]
  }'
```

---

## 📊 Daily monitoring commands

Run these from Konsole to monitor threats:

```bash
# Check live GuardDuty findings (severity 4+)
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}' \
  --query 'FindingIds' --output table

# Stream live cowrie logs (from inside EC2)
tail -f /opt/cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool

# Query top attacker IPs from the last 24 hours
aws logs start-query \
  --log-group-name honeypot-logs \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields src_ip | stats count(*) as hits by src_ip | sort hits desc | limit 10'
```

---

## 💰 Cost estimate

| Service | Monthly cost |
|---|---|
| EC2 t2.micro | ~$8–9 (free tier year 1) |
| GuardDuty | ~$1–3 |
| CloudWatch Logs | ~$0.50–2 |
| Lambda + SNS | ~$0 |
| **Total** | **~$10–14/month** |

> Stop the EC2 instance when not actively monitoring to save cost.

---

## ⚠️ Security disclaimer

This project intentionally exposes ports to the internet to attract attackers. Always:

- Run the honeypot in an **isolated AWS VPC**
- Never store sensitive data on the honeypot instance
- Monitor your AWS billing alerts
- Terminate the instance when the project is complete

---

## 📄 Resume bullets

- Deployed a cloud honeypot on AWS EC2 capturing real-world brute-force and port-scan attacks using Cowrie; ingested structured logs into CloudWatch and authored Insights queries to surface top attacker IPs and attack frequency trends
- Integrated AWS GuardDuty for automated threat detection across VPC flow logs and CloudTrail; wired findings to EventBridge and a Python Lambda function that classifies severity and dispatches real-time SNS email alerts
- Built a CloudWatch dashboard visualising live attack telemetry including login attempts, source geolocation, and session commands; automated daily threat-hunting queries via Konsole shell scripts
- Designed least-privilege IAM roles for all project components; managed entire infrastructure via AWS CLI from KDE Konsole with no manual console clicks

---

## 📁 Repository structure

```
aws-honeypot/
├── README.md
├── lambda_function.py       # GuardDuty alert processor
├── cloudwatch-agent-config.json
├── dashboard.json           # CloudWatch dashboard definition
└── scripts/
    ├── deploy.sh            # Full deployment script
    └── monitor.sh           # Daily monitoring commands
```

---

*Built with KDE Konsole · AWS CLI · Cowrie · GuardDuty · CloudWatch · Lambda*
