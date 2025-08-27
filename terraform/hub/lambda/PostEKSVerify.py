import os, json, boto3
s3=boto3.client('s3'); BUCKET=os.environ['S3_BUCKET']

def handler(event, ctx):
    role=event['roleArn']; region=event['region']; cluster=event['clusterName']; target=event['targetVersion']
    c=boto3.client('sts').assume_role(RoleArn=role, RoleSessionName='verify')['Credentials']
    eks=boto3.client('eks', region_name=region,
        aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'], aws_session_token=c['SessionToken'])
    upd = eks.describe_cluster(name=cluster)['cluster']
    status_ok = upd['status']=='ACTIVE' and upd['version']==target
    out={'cluster':cluster,'status':upd['status'],'version':upd['version'],'ok':status_ok}
    s3.put_object(Bucket=BUCKET, Key=f"eks/post_{cluster}.json", Body=json.dumps(out).encode('utf-8'))
    return {"hasIssues": (not status_ok), "details": out}
