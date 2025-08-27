import os
import json
import boto3
import uuid
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from botocore.exceptions import ClientError, BotoCoreError
from functools import wraps

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
)
logger = logging.getLogger(__name__)

class PreEKSCheckError(Exception):
    """Custom exception for pre-EKS check operations"""
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

def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0):
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
                    
                    if error_code in ['ValidationException', 'AccessDenied', 'ResourceNotFound']:
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
    
    # Get EKS waves from event
    eks_waves = event.get('eksWaves', [])
    if not eks_waves or not isinstance(eks_waves, list):
        raise PreEKSCheckError("Missing or invalid eksWaves in event")
    
    if len(eks_waves) == 0:
        raise PreEKSCheckError("No EKS waves provided for processing")
    
    # Validate each wave and target
    total_clusters = 0
    for i, wave in enumerate(eks_waves):
        if not isinstance(wave, dict):
            raise PreEKSCheckError(f"Wave {i} is not a valid dictionary")
        
        targets = wave.get('targets', [])
        if not isinstance(targets, list):
            raise PreEKSCheckError(f"Wave {i} targets is not a valid list")
        
        total_clusters += len(targets)
        
        # Validate each target cluster
        for j, cluster in enumerate(targets):
            if not isinstance(cluster, dict):
                raise PreEKSCheckError(f"Wave {i}, target {j} is not a valid dictionary")
            
            required_fields = ['roleArn', 'region', 'clusterName']
            for field in required_fields:
                if field not in cluster:
                    raise PreEKSCheckError(f"Missing required field '{field}' in wave {i}, target {j}")
                
                if not cluster[field] or not isinstance(cluster[field], str):
                    raise PreEKSCheckError(f"Invalid value for '{field}' in wave {i}, target {j}")
    
    # Validate environment variables
    bucket_name = os.environ.get('S3_BUCKET')
    if not bucket_name:
        raise PreEKSCheckError("S3_BUCKET environment variable not set")
    
    execution_id = event.get('executionId', f'eks-check-{int(time.time())}')
    
    return {
        'eks_waves': eks_waves,
        'bucket_name': bucket_name,
        'execution_id': execution_id,
        'total_clusters': total_clusters
    }

def assume_cross_account_role(role_arn: str, session_name: str = 'PreEKSCheck') -> Dict[str, str]:
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
            raise PreEKSCheckError(f"Access denied assuming role {role_arn}: {error_message}")
        elif error_code == 'InvalidUserType':
            raise PreEKSCheckError(f"Invalid user type for role assumption: {error_message}")
        else:
            raise PreEKSCheckError(f"Role assumption failed [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=3, base_delay=2.0)
def get_cluster_details(credentials: Dict[str, str], region: str, cluster_name: str) -> Dict[str, Any]:
    """Get EKS cluster details with comprehensive error handling"""
    
    try:
        eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Retrieving cluster details for {cluster_name} in {region}")
        
        # Get cluster description
        cluster_response = eks_client.describe_cluster(name=cluster_name)
        cluster_info = cluster_response['cluster']
        
        # Get cluster addons
        addons_response = eks_client.list_addons(clusterName=cluster_name)
        addons_list = addons_response.get('addons', [])
        
        # Get detailed addon information
        detailed_addons = []
        for addon_name in addons_list:
            try:
                addon_details = eks_client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                
                addon_info = addon_details['addon']
                detailed_addons.append({
                    'name': addon_name,
                    'version': addon_info.get('addonVersion', 'unknown'),
                    'status': addon_info.get('status', 'unknown'),
                    'health': addon_info.get('health', {}),
                    'configurationValues': addon_info.get('configurationValues', '{}'),
                    'tags': addon_info.get('tags', {})
                })
                
            except Exception as e:
                logger.warning(f"Failed to get details for addon {addon_name}: {str(e)}")
                detailed_addons.append({
                    'name': addon_name,
                    'version': 'unknown',
                    'status': 'unknown',
                    'error': str(e)
                })
        
        # Get node groups
        try:
            nodegroups_response = eks_client.list_nodegroups(clusterName=cluster_name)
            nodegroups = nodegroups_response.get('nodegroups', [])
            
            detailed_nodegroups = []
            for ng_name in nodegroups[:10]:  # Limit to first 10 to avoid excessive API calls
                try:
                    ng_details = eks_client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name
                    )
                    
                    ng_info = ng_details['nodegroup']
                    detailed_nodegroups.append({
                        'name': ng_name,
                        'status': ng_info.get('status', 'unknown'),
                        'instanceTypes': ng_info.get('instanceTypes', []),
                        'amiType': ng_info.get('amiType', 'unknown'),
                        'version': ng_info.get('version', 'unknown'),
                        'releaseVersion': ng_info.get('releaseVersion', 'unknown')
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to get details for nodegroup {ng_name}: {str(e)}")
                    detailed_nodegroups.append({
                        'name': ng_name,
                        'status': 'unknown',
                        'error': str(e)
                    })
        
        except Exception as e:
            logger.warning(f"Failed to list nodegroups for {cluster_name}: {str(e)}")
            detailed_nodegroups = []
        
        cluster_details = {
            'cluster_name': cluster_name,
            'region': region,
            'version': cluster_info.get('version', 'unknown'),
            'platform_version': cluster_info.get('platformVersion', 'unknown'),
            'status': cluster_info.get('status', 'unknown'),
            'endpoint': cluster_info.get('endpoint', ''),
            'role_arn': cluster_info.get('roleArn', ''),
            'vpc_config': cluster_info.get('vpcConfig', {}),
            'logging': cluster_info.get('logging', {}),
            'identity': cluster_info.get('identity', {}),
            'certificate_authority': cluster_info.get('certificateAuthority', {}),
            'addons': detailed_addons,
            'nodegroups': detailed_nodegroups,
            'addon_count': len(addons_list),
            'nodegroup_count': len(detailed_nodegroups),
            'created_at': cluster_info.get('createdAt', '').isoformat() if cluster_info.get('createdAt') else 'unknown',
            'tags': cluster_info.get('tags', {}),
            'check_timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Retrieved details for cluster {cluster_name}: {len(addons_list)} addons, {len(detailed_nodegroups)} nodegroups")
        
        return cluster_details
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to get cluster details: {error_code} - {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            raise PreEKSCheckError(f"EKS cluster {cluster_name} not found in region {region}")
        elif error_code == 'AccessDenied':
            raise PreEKSCheckError(f"Access denied to EKS cluster {cluster_name}: {error_message}")
        else:
            raise PreEKSCheckError(f"EKS describe_cluster failed [{error_code}]: {error_message}")

def analyze_cluster_health(cluster_details: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze cluster health and identify potential issues"""
    
    issues = []
    warnings = []
    
    cluster_name = cluster_details['cluster_name']
    cluster_status = cluster_details['status']
    cluster_version = cluster_details['version']
    
    # Check cluster status
    if cluster_status != 'ACTIVE':
        issues.append(f"Cluster status is {cluster_status} (expected ACTIVE)")
    
    # Check addons health
    addon_issues = 0
    for addon in cluster_details.get('addons', []):
        addon_status = addon.get('status', 'unknown')
        if addon_status not in ['ACTIVE', 'CREATING', 'UPDATING']:
            addon_issues += 1
            issues.append(f"Addon {addon['name']} has status {addon_status}")
    
    # Check nodegroup health  
    nodegroup_issues = 0
    for nodegroup in cluster_details.get('nodegroups', []):
        ng_status = nodegroup.get('status', 'unknown')
        if ng_status not in ['ACTIVE', 'CREATING', 'UPDATING']:
            nodegroup_issues += 1
            issues.append(f"NodeGroup {nodegroup['name']} has status {ng_status}")
    
    # Version warnings
    try:
        current_version = float(cluster_version)
        if current_version < 1.28:  # Example threshold
            warnings.append(f"Cluster version {cluster_version} is getting outdated")
    except (ValueError, TypeError):
        warnings.append(f"Unable to parse cluster version: {cluster_version}")
    
    # Generate health score
    total_components = 1 + len(cluster_details.get('addons', [])) + len(cluster_details.get('nodegroups', []))
    healthy_components = total_components - len(issues)
    health_score = (healthy_components / total_components) * 100 if total_components > 0 else 0.0
    
    health_analysis = {
        'cluster_name': cluster_name,
        'overall_health': 'healthy' if len(issues) == 0 else 'degraded' if len(issues) <= 2 else 'unhealthy',
        'health_score': round(health_score, 2),
        'issues_count': len(issues),
        'warnings_count': len(warnings),
        'issues': issues[:10],  # Limit for response size
        'warnings': warnings[:10],  # Limit for response size
        'recommendations': generate_recommendations(cluster_details, issues, warnings)
    }
    
    return health_analysis

def generate_recommendations(cluster_details: Dict[str, Any], issues: List[str], warnings: List[str]) -> List[str]:
    """Generate actionable recommendations based on cluster analysis"""
    
    recommendations = []
    
    # Cluster status recommendations
    if cluster_details['status'] != 'ACTIVE':
        recommendations.append("Monitor cluster status and investigate any ongoing issues")
    
    # Addon recommendations
    addon_issues = [issue for issue in issues if 'Addon' in issue]
    if addon_issues:
        recommendations.append("Review addon configurations and update any failing addons")
    
    # Nodegroup recommendations  
    nodegroup_issues = [issue for issue in issues if 'NodeGroup' in issue]
    if nodegroup_issues:
        recommendations.append("Check nodegroup scaling policies and instance health")
    
    # Version recommendations
    version_warnings = [warning for warning in warnings if 'version' in warning.lower()]
    if version_warnings:
        recommendations.append("Plan cluster version upgrade to maintain security and feature support")
    
    # General recommendations
    if len(issues) > 5:
        recommendations.append("Consider comprehensive cluster health review before patching")
    
    if not recommendations:
        recommendations.append("Cluster appears healthy and ready for patching operations")
    
    return recommendations

@retry_with_backoff(max_retries=3, base_delay=1.0)
def store_results_s3(bucket_name: str, s3_key: str, data: Dict[str, Any]) -> str:
    """Store pre-check results in S3 with comprehensive error handling"""
    
    try:
        s3_client = boto3.client('s3')
        
        # Convert data to JSON string with proper formatting
        json_data = json.dumps(data, indent=2, default=str, sort_keys=True)
        
        logger.info(f"Storing pre-check results to S3: s3://{bucket_name}/{s3_key}")
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=json_data.encode('utf-8'),
            ContentType='application/json',
            ServerSideEncryption='AES256',
            Metadata={
                'check-type': 'pre-eks-patching',
                'timestamp': str(int(time.time())),
                'cluster-count': str(len(data.get('clusters', [])))
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
            raise PreEKSCheckError(f"S3 bucket does not exist: {bucket_name}")
        elif error_code == 'AccessDenied':
            raise PreEKSCheckError(f"Access denied to S3 bucket: {bucket_name}")
        else:
            raise PreEKSCheckError(f"S3 storage failed [{error_code}]: {error_message}")

def process_cluster(cluster_config: Dict[str, Any]) -> Dict[str, Any]:
    """Process individual cluster check with comprehensive error handling"""
    
    cluster_name = cluster_config.get('clusterName', 'unknown')
    region = cluster_config.get('region', 'unknown')
    role_arn = cluster_config.get('roleArn', '')
    
    logger.info(f"Processing cluster {cluster_name} in region {region}")
    
    try:
        # Assume role in target account
        credentials = assume_cross_account_role(role_arn, 'PreEKSCheck')
        
        # Get cluster details
        cluster_details = get_cluster_details(credentials, region, cluster_name)
        
        # Analyze cluster health
        health_analysis = analyze_cluster_health(cluster_details)
        
        result = {
            'cluster': cluster_name,
            'region': region,
            'version': cluster_details['version'],
            'status': cluster_details['status'],
            'addons': [addon['name'] for addon in cluster_details.get('addons', [])],
            'addon_count': cluster_details['addon_count'],
            'nodegroup_count': cluster_details['nodegroup_count'],
            'health_analysis': health_analysis,
            'success': True,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Successfully processed cluster {cluster_name}: {health_analysis['overall_health']}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to process cluster {cluster_name}: {str(e)}")
        
        return {
            'cluster': cluster_name,
            'region': region,
            'version': 'unknown',
            'status': 'unknown',
            'addons': [],
            'addon_count': 0,
            'nodegroup_count': 0,
            'health_analysis': {
                'overall_health': 'error',
                'health_score': 0.0,
                'issues_count': 1,
                'issues': [str(e)],
                'recommendations': ['Resolve connectivity and authentication issues before patching']
            },
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'timestamp': datetime.utcnow().isoformat()
        }

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced pre-EKS check handler with comprehensive cluster analysis
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting pre-EKS check with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        eks_waves = validated_data['eks_waves']
        bucket_name = validated_data['bucket_name']
        execution_id = validated_data['execution_id']
        total_clusters = validated_data['total_clusters']
        
        logger.info(f"Processing {total_clusters} EKS clusters across {len(eks_waves)} waves")
        
        results = []
        healthy_clusters = 0
        degraded_clusters = 0
        unhealthy_clusters = 0
        
        # Process each wave and cluster
        for wave_index, wave in enumerate(eks_waves):
            targets = wave.get('targets', [])
            
            logger.info(f"Processing wave {wave_index + 1} with {len(targets)} clusters")
            
            for cluster_config in targets:
                result = process_cluster(cluster_config)
                results.append(result)
                
                if result['success']:
                    health = result['health_analysis']['overall_health']
                    if health == 'healthy':
                        healthy_clusters += 1
                    elif health == 'degraded':
                        degraded_clusters += 1
                    else:
                        unhealthy_clusters += 1
                else:
                    unhealthy_clusters += 1
        
        # Generate overall analysis
        overall_health_score = (healthy_clusters / total_clusters) * 100 if total_clusters > 0 else 0.0
        
        # Prepare data for S3 storage
        timestamp = datetime.utcnow().strftime('%Y/%m/%d/%H')
        s3_key = f"eks/{timestamp}/pre_eks_check_{execution_id}.json"
        
        storage_data = {
            'execution_id': execution_id,
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_clusters': total_clusters,
                'healthy_clusters': healthy_clusters,
                'degraded_clusters': degraded_clusters,
                'unhealthy_clusters': unhealthy_clusters,
                'overall_health_score': round(overall_health_score, 2),
                'waves_processed': len(eks_waves)
            },
            'clusters': results
        }
        
        # Store results in S3
        s3_url = store_results_s3(bucket_name, s3_key, storage_data)
        
        execution_time = time.time() - start_time
        
        final_result = {
            'statusCode': 200,
            'ok': True,
            'summary': storage_data['summary'],
            'clusters_ready': healthy_clusters + degraded_clusters,  # Allow degraded clusters to proceed with caution
            'clusters_blocked': unhealthy_clusters,
            's3_key': s3_key,
            's3_url': s3_url,
            'execution_id': execution_id,
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
        
        logger.info(f"Pre-EKS check completed in {execution_time:.2f}s")
        logger.info(f"Results: {healthy_clusters} healthy, {degraded_clusters} degraded, {unhealthy_clusters} unhealthy")
        
        return final_result
        
    except PreEKSCheckError as e:
        logger.error(f"Pre-EKS check error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'ok': False,
            'error': str(e),
            'error_type': 'PreEKSCheckError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in pre-EKS check handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'ok': False,
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
