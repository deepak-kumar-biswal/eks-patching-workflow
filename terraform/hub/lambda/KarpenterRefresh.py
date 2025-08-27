import os
import json
import boto3
import uuid
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from botocore.exceptions import ClientError, BotoCoreError
from functools import wraps

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
)
logger = logging.getLogger(__name__)

class KarpenterRefreshError(Exception):
    """Custom exception for Karpenter refresh operations"""
    pass

def with_correlation_id(func):
    """Decorator to add correlation ID to all log messages"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        correlation_id = str(uuid.uuid4())[:8]
        
        old_factory = logging.getLogRecordFactory()
        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.correlation_id = correlation_id
            return record
        
        logging.setLogRecordFactory(record_factory)
        
        try:
            return func(*args, **kwargs)
        finally:
            logging.setLogRecordFactory(old_factory)
    
    return wrapper

def retry_with_backoff(max_retries: int = 3, base_delay: float = 2.0):
    """Decorator for retry logic with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ClientError, BotoCoreError) as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown') if hasattr(e, 'response') else 'Unknown'
                    
                    if attempt == max_retries - 1:
                        logger.error(f"Final retry failed for {func.__name__}: {error_code} - {str(e)}")
                        raise
                    
                    if error_code in ['ValidationException', 'InvalidInstanceId', 'AccessDenied']:
                        logger.error(f"Non-retryable error: {error_code}")
                        raise
                    
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"Retry {attempt + 1}/{max_retries} for {func.__name__} after {delay}s: {error_code}")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

def validate_input(event: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and extract required parameters from event"""
    
    # Validate required fields
    required_fields = ['roleArn', 'region', 'targetVersion']
    for field in required_fields:
        if field not in event:
            raise KarpenterRefreshError(f"Missing required field: {field}")
        
        if not event[field] or not isinstance(event[field], str):
            raise KarpenterRefreshError(f"Invalid value for required field: {field}")
    
    role_arn = event['roleArn']
    region = event['region']
    target_version = event['targetVersion']
    
    # Validate Kubernetes version format
    if not target_version.replace('.', '').isdigit():
        raise KarpenterRefreshError(f"Invalid Kubernetes version format: {target_version}")
    
    # Validate IAM role ARN format
    if not role_arn.startswith('arn:aws:iam::'):
        raise KarpenterRefreshError(f"Invalid IAM role ARN format: {role_arn}")
    
    # Extract optional parameters
    controller_instance_id = event.get('controllerInstanceId')
    node_class_name = event.get('nodeClassName', 'default')
    namespace = event.get('namespace', 'karpenter')
    cluster_name = event.get('clusterName', 'unknown')
    execution_id = event.get('executionId', f'karpenter-refresh-{int(time.time())}')
    
    # Validate controller instance ID if provided
    if controller_instance_id and not controller_instance_id.startswith('i-'):
        raise KarpenterRefreshError(f"Invalid EC2 instance ID format: {controller_instance_id}")
    
    return {
        'role_arn': role_arn,
        'region': region,
        'target_version': target_version,
        'controller_instance_id': controller_instance_id,
        'node_class_name': node_class_name,
        'namespace': namespace,
        'cluster_name': cluster_name,
        'execution_id': execution_id
    }

def assume_cross_account_role(role_arn: str, session_name: str = 'KarpenterRefresh') -> Dict[str, str]:
    """Assume cross-account role with comprehensive error handling"""
    
    try:
        sts_client = boto3.client('sts')
        
        logger.info(f"Assuming role {role_arn}")
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'{session_name}-{int(time.time())}',
            DurationSeconds=3600  # 1 hour
        )
        
        credentials = response['Credentials']
        
        logger.info(f"Successfully assumed role {role_arn}")
        
        return {
            'AccessKeyId': credentials['AccessKeyId'],
            'SecretAccessKey': credentials['SecretAccessKey'],
            'SessionToken': credentials['SessionToken'],
            'Expiration': credentials['Expiration'].isoformat()
        }
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to assume role {role_arn}: {error_code} - {error_message}")
        
        if error_code == 'AccessDenied':
            raise KarpenterRefreshError(f"Access denied assuming role {role_arn}: {error_message}")
        elif error_code == 'InvalidUserType':
            raise KarpenterRefreshError(f"Invalid user type for role assumption: {error_message}")
        else:
            raise KarpenterRefreshError(f"Role assumption failed [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=2, base_delay=2.0)
def get_optimized_ami_id(region: str, kubernetes_version: str) -> Dict[str, Any]:
    """Get the optimized AMI ID for the specified Kubernetes version"""
    
    try:
        # Use hub account SSM to get the latest AMI ID
        ssm_client = boto3.client('ssm', region_name=region)
        
        ssm_parameter = f"/aws/service/eks/optimized-ami/{kubernetes_version}/amazon-linux-2/recommended/image_id"
        
        logger.info(f"Retrieving optimized AMI for Kubernetes {kubernetes_version}")
        
        response = ssm_client.get_parameter(Name=ssm_parameter)
        ami_id = response['Parameter']['Value']
        
        if not ami_id or not ami_id.startswith('ami-'):
            raise KarpenterRefreshError(f"Invalid AMI ID retrieved: {ami_id}")
        
        # Get additional AMI details
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            ami_response = ec2_client.describe_images(ImageIds=[ami_id])
            
            ami_details = {}
            if ami_response.get('Images'):
                image_info = ami_response['Images'][0]
                ami_details = {
                    'name': image_info.get('Name', ''),
                    'description': image_info.get('Description', ''),
                    'creation_date': image_info.get('CreationDate', ''),
                    'architecture': image_info.get('Architecture', ''),
                    'platform': image_info.get('Platform', 'linux')
                }
        
        except Exception as ami_detail_error:
            logger.warning(f"Failed to get AMI details: {str(ami_detail_error)}")
            ami_details = {}
        
        result = {
            'ami_id': ami_id,
            'kubernetes_version': kubernetes_version,
            'ssm_parameter': ssm_parameter,
            'details': ami_details
        }
        
        logger.info(f"Retrieved optimized AMI: {ami_id} for Kubernetes {kubernetes_version}")
        
        return result
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to get optimized AMI: {error_code} - {error_message}")
        
        if error_code == 'ParameterNotFound':
            raise KarpenterRefreshError(f"Optimized AMI not found for Kubernetes version {kubernetes_version}")
        elif error_code == 'AccessDenied':
            raise KarpenterRefreshError(f"Access denied to SSM parameter: {error_message}")
        else:
            raise KarpenterRefreshError(f"Failed to retrieve AMI ID [{error_code}]: {error_message}")

def generate_kubectl_commands(
    node_class_name: str,
    namespace: str,
    ami_id: str,
    kubernetes_version: str
) -> List[Dict[str, Any]]:
    """Generate kubectl commands for Karpenter node class update"""
    
    # Generate the patch command for EC2NodeClass
    patch_spec = {
        "spec": {
            "amiSelectorTerms": [
                {"id": ami_id}
            ],
            "metadata": {
                "annotations": {
                    "karpenter.sh/last-ami-update": datetime.utcnow().isoformat(),
                    "karpenter.sh/kubernetes-version": kubernetes_version
                }
            }
        }
    }
    
    # Create kubectl patch command
    patch_command = f"kubectl patch ec2nodeclass {node_class_name} -n {namespace} --type merge -p '{json.dumps(patch_spec)}'"
    
    # Create verification commands
    verify_command = f"kubectl get ec2nodeclass {node_class_name} -n {namespace} -o jsonpath='{{.spec.amiSelectorTerms[0].id}}'"
    status_command = f"kubectl get ec2nodeclass {node_class_name} -n {namespace} -o yaml"
    
    commands = [
        {
            'name': 'patch_nodeclass',
            'command': patch_command,
            'description': f'Update EC2NodeClass {node_class_name} with AMI {ami_id}',
            'critical': True
        },
        {
            'name': 'verify_update',
            'command': verify_command,
            'description': f'Verify AMI ID update for {node_class_name}',
            'critical': False
        },
        {
            'name': 'get_status',
            'command': status_command,
            'description': f'Get full status of {node_class_name}',
            'critical': False
        }
    ]
    
    return commands

@retry_with_backoff(max_retries=2, base_delay=3.0)
def execute_ssm_commands(
    credentials: Dict[str, str],
    region: str,
    instance_id: str,
    commands: List[Dict[str, Any]],
    execution_id: str
) -> Dict[str, Any]:
    """Execute kubectl commands via SSM with comprehensive error handling"""
    
    try:
        ssm_client = boto3.client(
            'ssm',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        # Prepare commands for execution
        command_list = []
        for cmd_info in commands:
            command_list.append(f"# {cmd_info['description']}")
            command_list.append(cmd_info['command'])
            command_list.append("echo '---'")
        
        # Add environment setup commands
        setup_commands = [
            "export KUBECONFIG=/etc/kubernetes/kubelet/kubeconfig",
            "export PATH=$PATH:/usr/local/bin",
            "echo 'Starting Karpenter refresh...'",
            ""  # Empty line for separation
        ]
        
        final_commands = setup_commands + command_list + [
            "echo 'Karpenter refresh completed'",
            f"echo 'Execution ID: {execution_id}'"
        ]
        
        logger.info(f"Executing {len(commands)} kubectl commands on instance {instance_id}")
        
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": final_commands},
            TimeoutSeconds=300,  # 5 minutes timeout
            CloudWatchOutputConfig={
                "CloudWatchOutputEnabled": True,
                "CloudWatchLogGroupName": "/aws/ssm/karpenter-refresh"
            },
            Comment=f"Karpenter node class refresh - {execution_id}"
        )
        
        command_id = response['Command']['CommandId']
        
        result = {
            'command_id': command_id,
            'instance_id': instance_id,
            'commands_executed': len(commands),
            'status': 'InProgress',
            'execution_id': execution_id,
            'cloudwatch_log_group': '/aws/ssm/karpenter-refresh'
        }
        
        logger.info(f"SSM command initiated: {command_id}")
        
        return result
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to execute SSM commands: {error_code} - {error_message}")
        
        if error_code == 'InvalidInstanceId':
            raise KarpenterRefreshError(f"Invalid or inaccessible instance ID: {instance_id}")
        elif error_code == 'AccessDenied':
            raise KarpenterRefreshError(f"Access denied to execute commands on instance {instance_id}: {error_message}")
        else:
            raise KarpenterRefreshError(f"SSM command execution failed [{error_code}]: {error_message}")

def get_karpenter_controller_instance(
    credentials: Dict[str, str],
    region: str,
    cluster_name: str
) -> Optional[str]:
    """Automatically detect Karpenter controller instance if not provided"""
    
    try:
        ec2_client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Searching for Karpenter controller instance for cluster {cluster_name}")
        
        # Search for instances with Karpenter tags
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': [f'*karpenter*', f'*controller*']},
                {'Name': 'tag:kubernetes.io/cluster/*', 'Values': ['owned']},
                {'Name': 'instance-state-name', 'Values': ['running']},
            ]
        )
        
        potential_instances = []
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                # Check if instance belongs to the right cluster
                cluster_tags = [key for key in tags.keys() if key.startswith('kubernetes.io/cluster/')]
                if any(cluster_name in tag for tag in cluster_tags):
                    potential_instances.append({
                        'instance_id': instance['InstanceId'],
                        'name': tags.get('Name', ''),
                        'launch_time': instance.get('LaunchTime', ''),
                        'tags': tags
                    })
        
        if potential_instances:
            # Sort by launch time and pick the most recent
            potential_instances.sort(key=lambda x: x.get('launch_time', ''), reverse=True)
            selected_instance = potential_instances[0]
            
            logger.info(f"Auto-detected Karpenter controller instance: {selected_instance['instance_id']}")
            return selected_instance['instance_id']
        
        logger.warning(f"No Karpenter controller instances found for cluster {cluster_name}")
        return None
        
    except Exception as e:
        logger.warning(f"Failed to auto-detect Karpenter controller instance: {str(e)}")
        return None

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced Karpenter refresh handler with comprehensive AMI management and kubectl execution
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting Karpenter refresh with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        role_arn = validated_data['role_arn']
        region = validated_data['region']
        target_version = validated_data['target_version']
        controller_instance_id = validated_data['controller_instance_id']
        node_class_name = validated_data['node_class_name']
        namespace = validated_data['namespace']
        cluster_name = validated_data['cluster_name']
        execution_id = validated_data['execution_id']
        
        logger.info(f"Refreshing Karpenter for cluster {cluster_name} with Kubernetes {target_version}")
        
        # Get optimized AMI ID
        ami_info = get_optimized_ami_id(region, target_version)
        ami_id = ami_info['ami_id']
        
        logger.info(f"Using optimized AMI: {ami_id}")
        
        # Assume role in target account
        credentials = assume_cross_account_role(role_arn, 'KarpenterRefresh')
        
        # Auto-detect controller instance if not provided
        if not controller_instance_id:
            controller_instance_id = get_karpenter_controller_instance(credentials, region, cluster_name)
            
            if not controller_instance_id:
                raise KarpenterRefreshError(
                    f"No controller instance ID provided and auto-detection failed for cluster {cluster_name}. "
                    "Please specify controllerInstanceId in the event."
                )
        
        logger.info(f"Using controller instance: {controller_instance_id}")
        
        # Generate kubectl commands
        kubectl_commands = generate_kubectl_commands(node_class_name, namespace, ami_id, target_version)
        
        # Execute commands via SSM
        command_result = execute_ssm_commands(
            credentials, region, controller_instance_id, kubectl_commands, execution_id
        )
        
        execution_time = time.time() - start_time
        
        result = {
            'statusCode': 200,
            'triggered': True,
            'ami': ami_id,
            'ami_details': ami_info.get('details', {}),
            'kubernetes_version': target_version,
            'node_class_name': node_class_name,
            'namespace': namespace,
            'controller_instance_id': controller_instance_id,
            'ssm_command': command_result,
            'kubectl_commands': len(kubectl_commands),
            'cluster_name': cluster_name,
            'execution_id': execution_id,
            'recommendations': [
                f"Monitor SSM command {command_result['command_id']} for execution status",
                f"Check CloudWatch logs at {command_result['cloudwatch_log_group']}",
                f"Verify node class update with: kubectl get ec2nodeclass {node_class_name} -n {namespace}",
                "Monitor node replacement and ensure new nodes use the updated AMI"
            ],
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
        
        logger.info(f"Karpenter refresh completed in {execution_time:.2f}s")
        logger.info(f"SSM Command ID: {command_result['command_id']}")
        
        return result
        
    except KarpenterRefreshError as e:
        logger.error(f"Karpenter refresh error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'triggered': False,
            'error': str(e),
            'error_type': 'KarpenterRefreshError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in Karpenter refresh handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'triggered': False,
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
