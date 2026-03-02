import argparse
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

import boto3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown security timeline from the CloudTrail detector lab."
    )
    parser.add_argument(
        "--table",
        "--alerts-table",
        dest="table_name",
        default=os.getenv("ALERTS_TABLE"),
        help="DynamoDB alerts table name (default: from ALERTS_TABLE env var).",
    )
    parser.add_argument(
        "--region",
        dest="region",
        default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1",
        help="AWS region to use (default: env/AWS_REGION or us-east-1).",
    )
    parser.add_argument(
        "--cloudtrail-bucket",
        dest="cloudtrail_bucket",
        default=os.getenv("CLOUDTRAIL_BUCKET"),
        help="Optional CloudTrail S3 bucket name to summarize recent log objects.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        default="timeline.md",
        help="Output Markdown file path (default: timeline.md).",
    )
    parser.add_argument(
        "--max-items",
        dest="max_items",
        type=int,
        default=500,
        help="Maximum number of alerts to include from DynamoDB scan (default: 500).",
    )
    parser.add_argument(
        "--max-s3-objects",
        dest="max_s3_objects",
        type=int,
        default=25,
        help="Maximum number of recent CloudTrail S3 objects to list (default: 25).",
    )
    return parser.parse_args()


def scan_alerts(table_name: str, region: str, max_items: int) -> List[Dict[str, Any]]:
    ddb = boto3.client("dynamodb", region_name=region)
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"TableName": table_name}

    while True:
        resp = ddb.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp or len(items) >= max_items:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    return items[:max_items]


def normalize_alert(item: Dict[str, Any]) -> Dict[str, Any]:
    def get_s(attr: str, default: str = "") -> str:
        val = item.get(attr, {})
        return val.get("S") or default

    ts_raw = get_s("timestamp")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.min

    raw_str = get_s("raw", "{}")
    try:
        raw_event = json.loads(raw_str)
    except Exception:
        raw_event = {}

    detail = raw_event.get("detail", {}) if isinstance(raw_event, dict) else {}

    return {
        "alert_id": get_s("alert_id"),
        "timestamp": ts,
        "timestamp_str": ts_raw or ts.isoformat() + "Z",
        "source": get_s("source", raw_event.get("source", "unknown")),
        "detail_type": get_s("detail_type", raw_event.get("detail-type", "unknown")),
        "event_name": get_s("event_name", detail.get("eventName", "unknown")),
        "user_identity": detail.get("userIdentity", {}),
        "aws_region": detail.get("awsRegion"),
        "raw_event": raw_event,
    }


def summarize_principal(user_identity: Any) -> str:
    if not isinstance(user_identity, dict):
        return "unknown"
    principal_id = user_identity.get("principalId") or "unknown"
    user_type = user_identity.get("type") or "UnknownType"
    username = user_identity.get("userName") or user_identity.get("sessionContext", {}).get(
        "sessionIssuer", {}
    ).get("userName")
    if username:
        return f"{user_type}:{username} ({principal_id})"
    return f"{user_type}:{principal_id}"


def list_recent_cloudtrail_objects(
    bucket: str, region: str, max_objects: int
) -> List[Dict[str, Any]]:
    s3 = boto3.client("s3", region_name=region)
    objects: List[Dict[str, Any]] = []
    continuation_token: Optional[str] = None

    while True:
        kwargs: Dict[str, Any] = {
            "Bucket": bucket,
            "MaxKeys": max_objects,
        }
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token

        resp = s3.list_objects_v2(**kwargs)
        contents = resp.get("Contents", [])
        objects.extend(contents)

        if not resp.get("IsTruncated") or len(objects) >= max_objects:
            break
        continuation_token = resp.get("NextContinuationToken")

    # Newest first
    objects.sort(key=lambda o: o.get("LastModified"), reverse=True)
    return objects[:max_objects]


def generate_markdown(
    alerts: List[Dict[str, Any]],
    cloudtrail_objects: Optional[List[Dict[str, Any]]],
    table_name: str,
    region: str,
    cloudtrail_bucket: Optional[str],
) -> str:
    lines: List[str] = []
    lines.append("# CloudTrail Detector Lab – Timeline Report")
    lines.append("")
    lines.append(f"- **Region**: `{region}`")
    lines.append(f"- **Alerts table**: `{table_name}`")
    if cloudtrail_bucket:
        lines.append(f"- **CloudTrail bucket**: `{cloudtrail_bucket}`")
    lines.append(f"- **Generated at**: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    if alerts:
        lines.append("## Alert timeline (from DynamoDB)")
        lines.append("")
        lines.append(
            "| Time (UTC) | EventName | DetailType | Source | Principal | AWS Region | Alert ID |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for a in alerts:
            principal = summarize_principal(a.get("user_identity"))
            lines.append(
                f"| {a['timestamp_str']} | {a['event_name']} | {a['detail_type']} | "
                f"{a['source']} | {principal} | {a.get('aws_region') or ''} | {a['alert_id']} |"
            )
        lines.append("")
    else:
        lines.append("## Alert timeline (from DynamoDB)")
        lines.append("")
        lines.append("_No alerts found in the DynamoDB table yet._")
        lines.append("")

    if cloudtrail_objects is not None:
        lines.append("## Recent CloudTrail log objects (from S3)")
        lines.append("")
        if cloudtrail_objects:
            lines.append("| LastModified | Size (bytes) | Key |")
            lines.append("| --- | --- | --- |")
            for obj in cloudtrail_objects:
                lm = obj.get("LastModified")
                lm_str = lm.isoformat() if hasattr(lm, "isoformat") else str(lm)
                size = obj.get("Size", 0)
                key = obj.get("Key", "")
                lines.append(f"| {lm_str} | {size} | `{key}` |")
            lines.append("")
        else:
            lines.append("_No CloudTrail objects found in the provided bucket (yet)._")
            lines.append("")

    lines.append("## How to use this report")
    lines.append("")
    lines.append(
        "Each row in the **Alert timeline** corresponds to an EventBridge event that "
        "triggered the detector Lambda and was written to DynamoDB."
    )
    lines.append(
        "You can take an `alert_id` and look up the full JSON event in the DynamoDB item "
        "(`raw` attribute) to pivot into more detailed investigation."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()

    if not args.table_name:
        raise SystemExit("You must provide a DynamoDB table name via --table or ALERTS_TABLE env var.")

    alerts_items = scan_alerts(args.table_name, args.region, args.max_items)
    normalized_alerts = [normalize_alert(it) for it in alerts_items]
    # Sort ascending by timestamp to build a timeline
    normalized_alerts.sort(key=lambda a: a["timestamp"])

    cloudtrail_objects: Optional[List[Dict[str, Any]]] = None
    if args.cloudtrail_bucket:
        try:
            cloudtrail_objects = list_recent_cloudtrail_objects(
                args.cloudtrail_bucket, args.region, args.max_s3_objects
            )
        except Exception as exc:
            # Don't fail the whole report if S3 listing is not permitted or empty
            print(f"Warning: could not list CloudTrail objects for bucket {args.cloudtrail_bucket}: {exc}")
            cloudtrail_objects = []

    md = generate_markdown(
        normalized_alerts,
        cloudtrail_objects,
        args.table_name,
        args.region,
        args.cloudtrail_bucket,
    )
    with open(args.output_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"Wrote timeline report to {args.output_path}")


if __name__ == "__main__":
    main()

