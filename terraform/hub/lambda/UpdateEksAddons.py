import json, boto3

def handler(event, ctx):
    t=event
    role=t['roleArn']; region=t['region']; cluster=t['clusterName']
    c=boto3.client('sts').assume_role(RoleArn=role, RoleSessionName='addons')['Credentials']
    eks=boto3.client('eks', region_name=region,
        aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'], aws_session_token=c['SessionToken'])
    curr = eks.list_addons(clusterName=cluster)['addons']
    results=[]
    for name in curr:
        vers = eks.describe_addon_versions(kubernetesVersion=t['targetVersion'], addonName=name)
        latest = vers['addons'][0]['addonVersions'][0]['addonVersion']
        resp = eks.update_addon(clusterName=cluster, addonName=name, addonVersion=latest, resolveConflicts='OVERWRITE')
        results.append({'addon':name, 'updateId':resp['update']['id']})
    return {"updated": results}
