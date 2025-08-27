import boto3

def handler(event, ctx):
    role=event['roleArn']; region=event['region']
    controller_instance_id = event.get('controllerInstanceId')
    c=boto3.client('sts').assume_role(RoleArn=role, RoleSessionName='karp')['Credentials']
    ssm=boto3.client('ssm', region_name=region,
        aws_access_key_id=c['AccessKeyId'], aws_secret_access_key=c['SecretAccessKey'], aws_session_token=c['SessionToken'])
    kver = event['targetVersion']
    ssm_param = f"/aws/service/eks/optimized-ami/{kver}/amazon-linux-2/recommended/image_id"
    ami = boto3.client('ssm', region_name=region).get_parameter(Name=ssm_param)['Parameter']['Value']
    patch_cmd = f"kubectl patch ec2nodeclass default -n karpenter --type merge -p '{{"spec":{"amiSelectorTerms":[{"id":"{ami}"}]}}}'"
    ssm.send_command(InstanceIds=[controller_instance_id], DocumentName="AWS-RunShellScript",
                     Parameters={"commands":[patch_cmd]}, CloudWatchOutputConfig={"CloudWatchOutputEnabled": True})
    return {"triggered": True, "ami": ami}
