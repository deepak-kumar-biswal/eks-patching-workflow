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

class PostEKSVerifyError(Exception):
    """Custom exception for post-EKS verification operations"""
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
                    
                    if error_code in ['ValidationException', 'ResourceNotFoundException', 'AccessDenied']:
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
    required_fields = ['roleArn', 'region', 'clusterName', 'targetVersion']
    for field in required_fields:
        if field not in event:
            raise PostEKSVerifyError(f"Missing required field: {field}")
        
        if not event[field] or not isinstance(event[field], str):
            raise PostEKSVerifyError(f"Invalid value for required field: {field}")
    
    role_arn = event['roleArn']
    region = event['region']
    cluster_name = event['clusterName']
    target_version = event['targetVersion']
    
    # Validate Kubernetes version format
    if not target_version.replace('.', '').isdigit():
        raise PostEKSVerifyError(f"Invalid Kubernetes version format: {target_version}")
    
    # Validate IAM role ARN format
    if not role_arn.startswith('arn:aws:iam::'):
        raise PostEKSVerifyError(f"Invalid IAM role ARN format: {role_arn}")
    
    # Validate environment variables
    bucket_name = os.environ.get('S3_BUCKET')
    if not bucket_name:
        raise PostEKSVerifyError("S3_BUCKET environment variable not set")
    
    execution_id = event.get('executionId', f'eks-verify-{int(time.time())}')
    
    return {
        'role_arn': role_arn,
        'region': region,
        'cluster_name': cluster_name,
        'target_version': target_version,
        'bucket_name': bucket_name,
        'execution_id': execution_id
    }

def assume_cross_account_role(role_arn: str, session_name: str = 'PostEKSVerify') -> Dict[str, str]:
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
            raise PostEKSVerifyError(f"Access denied assuming role {role_arn}: {error_message}")
        elif error_code == 'InvalidUserType':
            raise PostEKSVerifyError(f"Invalid user type for role assumption: {error_message}")
        else:
            raise PostEKSVerifyError(f"Role assumption failed [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=3, base_delay=2.0)
def get_cluster_status(credentials: Dict[str, str], region: str, cluster_name: str) -> Dict[str, Any]:
    """Get comprehensive EKS cluster status with error handling"""
    
    try:
        eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Retrieving cluster status for {cluster_name}")
        
        # Get cluster details
        cluster_response = eks_client.describe_cluster(name=cluster_name)
        cluster_info = cluster_response['cluster']
        
        # Get cluster addons with detailed status
        addons_response = eks_client.list_addons(clusterName=cluster_name)
        addon_names = addons_response.get('addons', [])
        
        detailed_addons = []
        addon_issues = []
        
        for addon_name in addon_names:
            try:
                addon_response = eks_client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                
                addon_info = addon_response['addon']
                addon_status = addon_info.get('status', 'unknown')
                addon_version = addon_info.get('addonVersion', 'unknown')
                
                detailed_addons.append({
                    'name': addon_name,
                    'version': addon_version,
                    'status': addon_status,
                    'health': addon_info.get('health', {}),
                    'issues': addon_info.get('health', {}).get('issues', [])
                })
                
                # Check for addon issues
                if addon_status not in ['ACTIVE', 'CREATING', 'UPDATING']:
                    addon_issues.append(f"Addon {addon_name} has status {addon_status}")
                
                health_issues = addon_info.get('health', {}).get('issues', [])
                if health_issues:
                    for issue in health_issues:
                        addon_issues.append(f"Addon {addon_name}: {issue.get('description', 'Unknown issue')}")
                
            except ClientError as e:
                logger.warning(f"Failed to describe addon {addon_name}: {e}")
                detailed_addons.append({
                    'name': addon_name,
                    'version': 'unknown',
                    'status': 'error',
                    'error': str(e)
                })
                addon_issues.append(f"Failed to check addon {addon_name}")
        
        # Get node groups status
        try:
            nodegroups_response = eks_client.list_nodegroups(clusterName=cluster_name)
            nodegroup_names = nodegroups_response.get('nodegroups', [])
            
            detailed_nodegroups = []
            nodegroup_issues = []
            
            for ng_name in nodegroup_names:
                try:
                    ng_response = eks_client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name
                    )
                    
                    ng_info = ng_response['nodegroup']
                    ng_status = ng_info.get('status', 'unknown')
                    ng_version = ng_info.get('version', 'unknown')
                    
                    detailed_nodegroups.append({
                        'name': ng_name,
                        'status': ng_status,
                        'version': ng_version,
                        'ami_type': ng_info.get('amiType', 'unknown'),
                        'instance_types': ng_info.get('instanceTypes', []),
                        'scaling_config': ng_info.get('scalingConfig', {}),
                        'health': ng_info.get('health', {})
                    })
                    
                    # Check for nodegroup issues
                    if ng_status not in ['ACTIVE', 'CREATING', 'UPDATING']:
                        nodegroup_issues.append(f"NodeGroup {ng_name} has status {ng_status}")
                    
                    health_issues = ng_info.get('health', {}).get('issues', [])
                    if health_issues:
                        for issue in health_issues:
                            nodegroup_issues.append(f"NodeGroup {ng_name}: {issue.get('description', 'Unknown issue')}")
                
                except ClientError as e:
                    logger.warning(f"Failed to describe nodegroup {ng_name}: {e}")
                    detailed_nodegroups.append({
                        'name': ng_name,
                        'status': 'error',
                        'error': str(e)
                    })
                    nodegroup_issues.append(f"Failed to check nodegroup {ng_name}")
        
        except Exception as e:
            logger.warning(f"Failed to get nodegroups: {str(e)}")
            detailed_nodegroups = []
            nodegroup_issues = ['Failed to retrieve nodegroup information']
        
        # Get update history
        try:
            updates_response = eks_client.list_updates(name=cluster_name)
            recent_updates = updates_response.get('updateIds', [])[:5]  # Last 5 updates
            
            update_history = []
            for update_id in recent_updates:
                try:
                    update_response = eks_client.describe_update(
                        name=cluster_name,
                        updateId=update_id
                    )
                    
                    update_info = update_response['update']
                    update_history.append({
                        'id': update_id,
                        'status': update_info.get('status', 'unknown'),
                        'type': update_info.get('type', 'unknown'),
                        'created_at': update_info.get('createdAt', '').isoformat() if update_info.get('createdAt') else 'unknown',
                        'errors': update_info.get('errors', [])
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to describe update {update_id}: {e}")
        
        except Exception as e:
            logger.warning(f"Failed to get update history: {str(e)}")
            update_history = []
        
        # Compile comprehensive cluster status
        cluster_status = {
            'cluster_name': cluster_name,
            'region': region,
            'status': cluster_info.get('status', 'unknown'),
            'version': cluster_info.get('version', 'unknown'),
            'platform_version': cluster_info.get('platformVersion', 'unknown'),
            'endpoint': cluster_info.get('endpoint', ''),
            'created_at': cluster_info.get('createdAt', '').isoformat() if cluster_info.get('createdAt') else 'unknown',
            'role_arn': cluster_info.get('roleArn', ''),
            'vpc_config': cluster_info.get('vpcConfig', {}),
            'logging': cluster_info.get('logging', {}),
            'addons': detailed_addons,
            'nodegroups': detailed_nodegroups,
            'update_history': update_history,
            'addon_count': len(detailed_addons),
            'nodegroup_count': len(detailed_nodegroups),
            'issues': {
                'cluster_issues': [],
                'addon_issues': addon_issues,
                'nodegroup_issues': nodegroup_issues
            },
            'verification_timestamp': datetime.utcnow().isoformat()
        }
        
        # Check for cluster-level issues
        if cluster_info.get('status') != 'ACTIVE':
            cluster_status['issues']['cluster_issues'].append(f"Cluster status is {cluster_info.get('status')} (expected ACTIVE)")
        
        logger.info(f"Retrieved comprehensive status for cluster {cluster_name}")
        
        return cluster_status
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to get cluster status: {error_code} - {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            raise PostEKSVerifyError(f"EKS cluster {cluster_name} not found in region {region}")
        elif error_code == 'AccessDenied':
            raise PostEKSVerifyError(f"Access denied to EKS cluster {cluster_name}: {error_message}")
        else:
            raise PostEKSVerifyError(f"Failed to describe cluster [{error_code}]: {error_message}")

def analyze_cluster_verification(cluster_status: Dict[str, Any], target_version: str) -> Dict[str, Any]:
    """Analyze cluster verification results and determine success/issues"""
    
    cluster_name = cluster_status['cluster_name']
    current_version = cluster_status['version']
    cluster_state = cluster_status['status']
    
    # Primary verification checks
    version_matches = current_version == target_version
    cluster_active = cluster_state == 'ACTIVE'
    
    # Collect all issues
    all_issues = []
    all_issues.extend(cluster_status['issues']['cluster_issues'])
    all_issues.extend(cluster_status['issues']['addon_issues'])
    all_issues.extend(cluster_status['issues']['nodegroup_issues'])
    
    # Version verification
    if not version_matches:
        all_issues.append(f"Version mismatch: expected {target_version}, found {current_version}")
    
    # Cluster state verification
    if not cluster_active:
        all_issues.append(f"Cluster not active: status is {cluster_state}")
    
    # Addon health analysis
    addon_health_score = 0.0
    total_addons = len(cluster_status.get('addons', []))
    
    if total_addons > 0:
        healthy_addons = sum(1 for addon in cluster_status['addons'] if addon.get('status') == 'ACTIVE')
        addon_health_score = (healthy_addons / total_addons) * 100
    else:
        addon_health_score = 100.0  # No addons = no addon issues
    
    # NodeGroup health analysis
    nodegroup_health_score = 0.0
    total_nodegroups = len(cluster_status.get('nodegroups', []))
    
    if total_nodegroups > 0:
        healthy_nodegroups = sum(1 for ng in cluster_status['nodegroups'] if ng.get('status') == 'ACTIVE')
        nodegroup_health_score = (healthy_nodegroups / total_nodegroups) * 100
    else:
        nodegroup_health_score = 100.0  # No nodegroups managed by EKS
    
    # Overall health calculation
    health_components = [
        100.0 if version_matches else 0.0,  # Version check (critical)
        100.0 if cluster_active else 0.0,   # Cluster state (critical)
        addon_health_score,                  # Addon health
        nodegroup_health_score              # NodeGroup health
    ]
    
    overall_health_score = sum(health_components) / len(health_components)
    
    # Determine verification status
    if version_matches and cluster_active and len(all_issues) == 0:
        verification_status = 'success'
        has_issues = False
    elif version_matches and cluster_active and len(all_issues) <= 2:
        verification_status = 'success_with_warnings'
        has_issues = True
    else:
        verification_status = 'failed'
        has_issues = True
    
    verification_result = {
        'verification_status': verification_status,
        'has_issues': has_issues,
        'version_matches': version_matches,
        'cluster_active': cluster_active,
        'target_version': target_version,
        'current_version': current_version,
        'current_status': cluster_state,
        'overall_health_score': round(overall_health_score, 2),
        'health_breakdown': {
            'version_check': 100.0 if version_matches else 0.0,
            'cluster_state': 100.0 if cluster_active else 0.0,
            'addon_health': round(addon_health_score, 2),
            'nodegroup_health': round(nodegroup_health_score, 2)
        },
        'issues_count': len(all_issues),
        'issues': all_issues[:10],  # Limit for response size
        'recommendations': generate_verification_recommendations(
            verification_status, version_matches, cluster_active, all_issues
        )
    }
    
    return verification_result

def generate_verification_recommendations(
    verification_status: str,
    version_matches: bool,
    cluster_active: bool,
    issues: List[str]
) -> List[str]:
    """Generate actionable recommendations based on verification results"""
    
    recommendations = []
    
    if verification_status == 'success':
        recommendations.append("✅ EKS cluster update verification successful")
        recommendations.append("Monitor cluster health for the next 24 hours")
        recommendations.append("Validate application functionality on updated cluster")
    
    elif verification_status == 'success_with_warnings':
        recommendations.append("⚠️ Cluster updated successfully but with minor issues")
        recommendations.append("Review and address the identified warnings")
        recommendations.append("Monitor cluster metrics and logs for anomalies")
    
    else:  # failed
        if not version_matches:
            recommendations.append("🔄 Cluster version update may still be in progress - wait and re-verify")
            recommendations.append("Check EKS update history for any failed updates")
        
        if not cluster_active:
            recommendations.append("🚨 Cluster is not in ACTIVE state - immediate attention required")
            recommendations.append("Check AWS Health Dashboard for any service issues")
        
        if len(issues) > 5:
            recommendations.append("🔍 Multiple issues detected - perform comprehensive health check")
        
        recommendations.append("Contact AWS Support if issues persist")
    
    # Add specific recommendations based on issue types
    addon_issues = [issue for issue in issues if 'Addon' in issue]
    if addon_issues:
        recommendations.append("🔧 Review addon configurations and update any failing addons")
    
    nodegroup_issues = [issue for issue in issues if 'NodeGroup' in issue]
    if nodegroup_issues:
        recommendations.append("🖥️ Check nodegroup health and instance status")
    
    return recommendations

@retry_with_backoff(max_retries=3, base_delay=1.0)
def store_verification_results(bucket_name: str, s3_key: str, data: Dict[str, Any]) -> str:
    """Store verification results in S3 with comprehensive error handling"""
    
    try:
        s3_client = boto3.client('s3')
        
        # Convert data to JSON string with proper formatting
        json_data = json.dumps(data, indent=2, default=str, sort_keys=True)
        
        logger.info(f"Storing verification results to S3: s3://{bucket_name}/{s3_key}")
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=json_data.encode('utf-8'),
            ContentType='application/json',
            ServerSideEncryption='AES256',
            Metadata={
                'verification-type': 'post-eks-update',
                'timestamp': str(int(time.time())),
                'cluster-name': data.get('cluster_status', {}).get('cluster_name', 'unknown')
            }
        )
        
        s3_url = f"s3://{bucket_name}/{s3_key}"
        logger.info(f"Successfully stored results: {s3_url}")
        
        return s3_url
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to store results to S3: {error_code} - {error_message}")
        
        if error_code == 'NoSuchBucket':
            raise PostEKSVerifyError(f"S3 bucket does not exist: {bucket_name}")
        elif error_code == 'AccessDenied':
            raise PostEKSVerifyError(f"Access denied to S3 bucket: {bucket_name}")
        else:
            raise PostEKSVerifyError(f"S3 storage failed [{error_code}]: {error_message}")

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced post-EKS verification handler with comprehensive cluster analysis
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting post-EKS verification with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        role_arn = validated_data['role_arn']
        region = validated_data['region']
        cluster_name = validated_data['cluster_name']
        target_version = validated_data['target_version']
        bucket_name = validated_data['bucket_name']
        execution_id = validated_data['execution_id']
        
        logger.info(f"Verifying EKS cluster {cluster_name} update to version {target_version}")
        
        # Assume role in target account
        credentials = assume_cross_account_role(role_arn, 'PostEKSVerify')
        
        # Get comprehensive cluster status
        cluster_status = get_cluster_status(credentials, region, cluster_name)
        
        # Analyze verification results
        verification_analysis = analyze_cluster_verification(cluster_status, target_version)
        
        # Prepare data for S3 storage
        timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
        s3_key = f"eks/{timestamp}/post_eks_verify_{cluster_name}_{execution_id}.json"
        
        storage_data = {
            'execution_id': execution_id,
            'timestamp': datetime.utcnow().isoformat(),
            'cluster_status': cluster_status,
            'verification_analysis': verification_analysis,
            'target_version': target_version
        }
        
        # Store results in S3
        s3_url = store_verification_results(bucket_name, s3_key, storage_data)
        
        execution_time = time.time() - start_time
        
        result = {
            'statusCode': 200,
            'hasIssues': verification_analysis['has_issues'],
            'verification_status': verification_analysis['verification_status'],
            'details': {
                'cluster': cluster_name,
                'status': cluster_status['status'],
                'version': cluster_status['version'],
                'target_version': target_version,
                'version_matches': verification_analysis['version_matches'],
                'overall_health_score': verification_analysis['overall_health_score']
            },
            'issues': verification_analysis['issues'],
            'recommendations': verification_analysis['recommendations'],
            's3_key': s3_key,
            's3_url': s3_url,
            'execution_id': execution_id,
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
        
        logger.info(f"Post-EKS verification completed in {execution_time:.2f}s")
        logger.info(f"Verification status: {verification_analysis['verification_status']}")
        
        return result
        
    except PostEKSVerifyError as e:
        logger.error(f"Post-EKS verification error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'hasIssues': True,
            'verification_status': 'error',
            'error': str(e),
            'error_type': 'PostEKSVerifyError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in post-EKS verification handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'hasIssues': True,
            'verification_status': 'error',
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
