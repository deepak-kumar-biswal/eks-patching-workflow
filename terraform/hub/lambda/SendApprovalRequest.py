import os, urllib.parse, boto3, json

sns = boto3.client('sns')
def handler(event, context):
    token = event['taskToken']
    details = event.get('details', {})
    base = os.environ['APIGW_BASE']
    approve = f"{base}/callback?action=approve&token={urllib.parse.quote(token)}"
    reject  = f"{base}/callback?action=reject&token={urllib.parse.quote(token)}"
    msg = {
        "subject": event.get("subject","Approval required"),
        "body": (
            "Manual approval required for maintenance.\n\n"
            f"Details: {json.dumps(details)}\n\n"
            f"Approve: {approve}\n"
            f"Reject:  {reject}\n"
        )
    }
    sns.publish(TopicArn=os.environ['TOPIC_ARN'], Subject=msg["subject"], Message=msg["body"])
    return {"notified": True}
