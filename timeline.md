# CloudTrail Detector Lab – Timeline Report

- **Region**: `us-east-1`
- **Alerts table**: `ctd-lab-237422644469-alerts`
- **CloudTrail bucket**: `ctd-lab-237422644469-cloudtrail-logs`
- **Generated at**: 2026-03-02T07:11:39.870142Z

## Alert timeline (from DynamoDB)

| Time (UTC) | EventName | DetailType | Source | Principal | AWS Region | Alert ID |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-03-02T06:48:43.856557Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 5f063a03-af14-4ee0-99cc-0c629fe9a496 |
| 2026-03-02T06:49:28.908093Z | CreateAccessKey | AWS API Call via CloudTrail | aws.iam | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | 43507167-e919-434c-9155-17b17f8e1654 |
| 2026-03-02T06:50:43.096628Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | f8f7dca3-723f-455b-a453-9dcd4cb23982 |
| 2026-03-02T06:52:43.121679Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 6f53bc03-f5bd-414e-8ec2-c44bcf503e0e |
| 2026-03-02T06:52:58.301648Z | DeleteAccessKey | AWS API Call via CloudTrail | aws.iam | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | b30e84c8-32a1-4983-856a-32ee72548af9 |
| 2026-03-02T06:54:43.060473Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 0700db28-2d87-4fb0-853b-8c8c66d97717 |
| 2026-03-02T06:55:32.349339Z | DeleteAccessKey | AWS API Call via CloudTrail | aws.iam | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | 6ae607a8-d852-41d6-8ae3-dba05e98ee0c |
| 2026-03-02T06:56:43.038116Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | e1c90bb8-cac9-4e61-88ca-b9db8d800fdc |
| 2026-03-02T06:58:42.979515Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 8a6ca5df-5b6a-4e78-898d-7032b467b2f3 |
| 2026-03-02T06:58:53.138450Z | DeleteAccessKey | AWS API Call via CloudTrail | aws.iam | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | a18ef8df-6cb3-4597-a81f-77ca21914925 |
| 2026-03-02T06:59:16.727665Z | StopLogging | AWS API Call via CloudTrail | aws.cloudtrail | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | 0507dc92-78ea-40b0-a9bb-7a290af768d5 |
| 2026-03-02T07:00:08.128857Z | ScheduleKeyDeletion | AWS API Call via CloudTrail | aws.kms | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | dd950a2e-dc17-4fcb-9e90-12580fb615cc |
| 2026-03-02T07:00:42.973875Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | a8ed5a29-5cdc-4229-b8f0-3fc06c6760d1 |
| 2026-03-02T07:02:42.978985Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 9d0fc72d-88bd-4ad6-a39e-9810c4876bf1 |
| 2026-03-02T07:02:59.156604Z | ScheduleKeyDeletion | AWS API Call via CloudTrail | aws.kms | IAMUser:terraform-admin (AIDATOR36BT2U3D54T6CL) | us-east-1 | 76649b2a-aab4-4787-98e0-6f58ff045ca9 |
| 2026-03-02T07:04:43.195375Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | e066ac40-278e-4e32-8428-eb241937fd5b |
| 2026-03-02T07:06:43.112522Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | 7482e76f-9bfa-4ce1-ac96-674ac6c1fa32 |
| 2026-03-02T07:08:43.133446Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | e6a0b43a-162a-4448-9e65-48db352f04ed |
| 2026-03-02T07:10:43.060279Z | unknown | Scheduled Event | aws.events | UnknownType:unknown |  | afeb5f1a-e8dd-4679-b550-21fb589c57e8 |

## Recent CloudTrail log objects (from S3)

_No CloudTrail objects found in the provided bucket (yet)._

## How to use this report

Each row in the **Alert timeline** corresponds to an EventBridge event that triggered the detector Lambda and was written to DynamoDB.
You can take an `alert_id` and look up the full JSON event in the DynamoDB item (`raw` attribute) to pivot into more detailed investigation.
