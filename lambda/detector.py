import os
import json
import uuid
import datetime
import boto3

ddb = boto3.client("dynamodb")
TABLE = os.environ["ALERTS_TABLE"]

def lambda_handler(event, context):
    # EventBridge will pass the CloudTrail-shaped event here later
    alert_id = str(uuid.uuid4())
    ts = datetime.datetime.utcnow().isoformat() + "Z"

    item = {
        "alert_id": {"S": alert_id},
        "timestamp": {"S": ts},
        "source": {"S": event.get("source", "unknown")},
        "detail_type": {"S": event.get("detail-type", "unknown")},
        "event_name": {"S": event.get("detail", {}).get("eventName", "unknown")},
        "raw": {"S": json.dumps(event)[:350000]},  # DynamoDB item size limit guard
    }

    ddb.put_item(TableName=TABLE, Item=item)
    return {"status": "ok", "alert_id": alert_id}
