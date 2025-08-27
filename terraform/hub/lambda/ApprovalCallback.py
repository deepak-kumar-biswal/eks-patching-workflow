import json, urllib.parse, boto3, os

sf = boto3.client('stepfunctions')

def handler(event, context):
    qs = event.get('queryStringParameters') or {}
    action = qs.get('action')
    token = qs.get('token')
    if not token or action not in ('approve','reject'):
        return {"statusCode": 400, "body": "Missing or invalid parameters"}
    if action == 'approve':
        sf.send_task_success(taskToken=token, output=json.dumps({"approved": True}))
        body = "Approved. State machine will continue."
    else:
        sf.send_task_failure(taskToken=token, error="Rejected", cause="Operator rejected change")
        body = "Rejected. State machine marked as failure."
    return {"statusCode": 200, "body": body}
