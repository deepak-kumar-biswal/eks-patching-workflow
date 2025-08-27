import os, json, boto3
s3=boto3.client('s3'); BUCKET=os.environ['S3_BUCKET']

def handler(event, ctx):
    out=[]
    for t in event.get('eksWaves', []):
        for cluster in t.get('targets', []):
            role=cluster['roleArn']; region=cluster['region']; name=cluster['clusterName']
            c=boto3.client('sts').assume_role(RoleArn=role, RoleSessionName='preeks')['Credentials']
            eks=boto3.client('eks', region_name=region,
                aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'], aws_session_token=c['SessionToken'])
            desc=eks.describe_cluster(name=name)['cluster']
            addons=eks.list_addons(clusterName=name)['addons']
            out.append({'cluster':name,'version':desc['version'],'addons':addons,'region':region})
    s3.put_object(Bucket=BUCKET, Key=f"eks/pre.json", Body=json.dumps(out).encode('utf-8'))
    return {"ok": True}
