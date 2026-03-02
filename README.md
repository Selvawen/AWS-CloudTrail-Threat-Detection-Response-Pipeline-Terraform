# CloudTrail Threat Detection & Automated Logging Lab

<img width="500" height="auto" alt="terraform aws" src="https://github.com/user-attachments/assets/7b62cfab-2efc-4df6-a916-0f8c6de3f294" />


This project documents the design and implementation of a cloud-native detection pipeline in AWS. The goal was to simulate sensitive API activity, detect it in near real-time, and store structured alert data for analysis.

Rather than simply provisioning resources, this lab demonstrates how activity inside an AWS account can be monitored, detected, and preserved for investigation.

---

## Architecture Overview

The environment consists of the following AWS services:

- **AWS CloudTrail** – Records all API activity in the account  
- **Amazon S3** – Stores CloudTrail log files  
- **Amazon EventBridge** – Filters high-risk API calls  
- **AWS Lambda** – Processes matched security events  
- **Amazon DynamoDB** – Stores structured alert records  
- **Amazon CloudWatch** – Provides execution logs and visibility  

## High-Level Diagram

``` mermaid
flowchart TD
    subgraph AWS["AWS (us-east-1)"]
        CT[CloudTrail trail]
        S3[(S3 bucket)]
        subgraph EB["EventBridge Rules"]
            R1[IAM CreateAccessKey]
            R2[IAM DeleteAccessKey]
            R3[CloudTrail Tampering]
            R4[KMS ScheduleKeyDeletion]
        end
        L[Lambda Detector]
        DDB[(DynamoDB Alerts Table)]
    end

    subgraph Local["Local Machine"]
        PY[report_generate_timeline.py]
        MD[timeline.md]
    end

    CT --> S3
    CT --> R1
    CT --> R2
    CT --> R3
    CT --> R4
    R1 --> L
    R2 --> L
    R3 --> L
    R4 --> L
    L --> DDB
    PY --> DDB
    PY --> S3
    PY --> MD
```


### Detection Flow

CloudTrail → EventBridge → Lambda → DynamoDB

---

## Step 1 – Enabling Visibility (CloudTrail → S3)

The first step was provisioning a CloudTrail trail and S3 bucket in `us-east-1` to ensure all API activity was recorded.

CloudTrail immediately began writing log files to the S3 bucket.

### Evidence

Terraform-created CloudTrail S3 bucket:

<img width="800" height="318" alt="1-Terraform‑created CloudTrail S3 bucket in us‑east‑1" src="https://github.com/user-attachments/assets/87a4a365-16da-4dfd-8a2b-50ae1fbe3849" />


CloudTrail log files actively being written:

<img width="800" height="905" alt="2-CloudTrail log files being written into the S3 bucket" src="https://github.com/user-attachments/assets/4a107f4b-0620-4964-858a-1de577fadbf7" />


At this stage, the infrastructure was passively collecting all account activity — including IAM and KMS operations.

---

## Step 2 – Defining What “Suspicious” Looks Like

Next, I created EventBridge rules to detect sensitive API calls, including:

- `CreateAccessKey`
- `DeleteAccessKey`
- `StopLogging`
- `ScheduleKeyDeletion`

These actions commonly indicate:

- Credential manipulation
- Attempted logging tampering
- Encryption key destruction

### EventBridge Rules

<img width="800" height="633" alt="eventbridge rules" src="https://github.com/user-attachments/assets/c118cfa5-02ff-4562-8030-1ea98bf8b3b6" />


Instead of manually reviewing logs, the system now automatically reacts to specific high-risk activity.

---

## Step 3 – Simulating Security-Relevant Activity

To validate detection, I intentionally performed sensitive API actions such as:

- Creating IAM access keys  
- Deleting IAM access keys  
- Scheduling KMS key deletion  
- Attempting CloudTrail logging modification  

These actions generated CloudTrail entries that matched the EventBridge rules.

This confirmed that the monitoring layer correctly identified risky behavior in real time.

---

## Step 4 – Automated Detection via Lambda

When EventBridge detects a matching event, it invokes a Python Lambda function.

The Lambda function:

- Generates a unique alert ID  
- Timestamps the event  
- Extracts event source and event name  
- Stores the raw event JSON  
- Writes structured alert data into DynamoDB  

### Lambda Implementation

Lambda code:

<img width="800" height="538" alt="lambda code source" src="https://github.com/user-attachments/assets/1eba0e6c-1f3f-4399-8a95-40366f99dff9" />




Environment variables:

<img width="800" height="181" alt="lambda environment variables" src="https://github.com/user-attachments/assets/2ddd62e7-b459-49ae-a223-4fd4f832c4db" />




Runtime configuration:

<img width="800" height="260" alt="lambda runtime settings" src="https://github.com/user-attachments/assets/f4c30f13-7173-4825-97e1-33643c9d5b31" />



This demonstrates serverless development and runtime configuration management within AWS.

---

## Step 5 – Observability and Validation

CloudWatch logs confirmed that:

- EventBridge successfully invoked Lambda  
- Events were processed without error  
- Execution duration and memory usage remained within limits  

Lambda execution logs:

<img width="800" height="787" alt="Cloudwatch-LambdaInvoked" src="https://github.com/user-attachments/assets/e6997255-1a32-4e94-ab54-56de562ee374" />


Log stream details:

<img width="800" height="199" alt="Cloudwatch-LogStream" src="https://github.com/user-attachments/assets/5ec16dd9-9d9c-47ce-927a-952d24499ba0" />



This validated that the detection pipeline was functioning end-to-end.

---

## Step 6 – Alert Storage in DynamoDB

Each detected event was stored as a structured record in DynamoDB.

The table includes:

- `alert_id`
- `timestamp`
- `source`
- `detail_type`
- `event_name`
- `raw` event payload

DynamoDB alert records:

<img width="800" height="184" alt="dynamoDB tables alerts" src="https://github.com/user-attachments/assets/2d81568e-b231-4813-958f-934f8bf716a5" />



Expanded table view:

<img width="800" height="631" alt="dynamoDB" src="https://github.com/user-attachments/assets/44b2e125-5397-47ad-a234-62150e9c6b29" />



This enables:

- Structured security telemetry storage  
- Evidence preservation  
- Historical event review  
- Queryable alert tracking  

---

## What Happened in the Environment

During testing, the following activity was successfully detected and logged:

- IAM access key creation  
- IAM access key deletion  
- KMS key deletion scheduling  
- CloudTrail stop logging attempts  

Each event followed this path:

1. Recorded by CloudTrail  
2. Matched by an EventBridge rule  
3. Triggered a Lambda execution  
4. Written to DynamoDB as a structured alert  

The infrastructure captured both routine scheduled events and high-risk API activity, demonstrating detection precision.

---

## Skills Demonstrated

### Cloud & Security Engineering

- Designing event-driven detection pipelines  
- Monitoring IAM and KMS activity  
- Detecting logging tampering attempts  
- Understanding AWS API telemetry  

### Serverless Development

- Writing Python Lambda functions  
- Handling structured JSON events  
- Managing environment variables  
- Configuring runtime environments  

### Infrastructure & Observability

- Implementing CloudTrail logging architecture  
- Configuring EventBridge filtering logic  
- Validating execution in CloudWatch  
- Designing DynamoDB schemas for alert storage  

### Security Mindset

- Identifying high-risk API behavior  
- Simulating adversary-like actions  
- Preserving forensic evidence  
- Building automated detection instead of manual review  

---

## Summary

This project simulates real-world cloud threat detection inside an AWS environment.

It demonstrates how API activity can be:

- Captured  
- Filtered  
- Processed  
- Stored  
- Verified  

Instead of manually reviewing logs, this infrastructure automatically identifies sensitive activity and preserves it in a structured, queryable format.

This reflects practical experience in:

- Cloud detection engineering  
- AWS-native security tooling  
- Event-driven automation  
- Incident visibility design  
