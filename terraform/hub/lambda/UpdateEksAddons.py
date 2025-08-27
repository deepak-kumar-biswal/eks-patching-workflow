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

class EKSAddonUpdateError(Exception):
    """Custom exception for EKS addon update operations"""
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
                    
                    if error_code in ['ValidationException', 'InvalidParameterException', 'ResourceNotFoundException']:
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
            raise EKSAddonUpdateError(f"Missing required field: {field}")
        
        if not event[field] or not isinstance(event[field], str):
            raise EKSAddonUpdateError(f"Invalid value for required field: {field}")
    
    role_arn = event['roleArn']
    region = event['region']
    cluster_name = event['clusterName']
    target_version = event['targetVersion']
    
    # Validate Kubernetes version format
    if not target_version.replace('.', '').isdigit():
        raise EKSAddonUpdateError(f"Invalid Kubernetes version format: {target_version}")
    
    # Validate IAM role ARN format
    if not role_arn.startswith('arn:aws:iam::'):
        raise EKSAddonUpdateError(f"Invalid IAM role ARN format: {role_arn}")
    
    # Extract optional parameters
    resolve_conflicts = event.get('resolveConflicts', 'OVERWRITE')
    if resolve_conflicts not in ['OVERWRITE', 'PRESERVE']:
        resolve_conflicts = 'OVERWRITE'
    
    service_account_role_arn = event.get('serviceAccountRoleArn')
    execution_id = event.get('executionId', f'addon-update-{int(time.time())}')
    
    return {
        'role_arn': role_arn,
        'region': region,
        'cluster_name': cluster_name,
        'target_version': target_version,
        'resolve_conflicts': resolve_conflicts,
        'service_account_role_arn': service_account_role_arn,
        'execution_id': execution_id
    }

def assume_cross_account_role(role_arn: str, session_name: str = 'EKSAddonUpdate') -> Dict[str, str]:
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
            raise EKSAddonUpdateError(f"Access denied assuming role {role_arn}: {error_message}")
        elif error_code == 'InvalidUserType':
            raise EKSAddonUpdateError(f"Invalid user type for role assumption: {error_message}")
        else:
            raise EKSAddonUpdateError(f"Role assumption failed [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=3, base_delay=2.0)
def get_current_addons(credentials: Dict[str, str], region: str, cluster_name: str) -> List[Dict[str, Any]]:
    """Get current addon information with comprehensive error handling"""
    
    try:
        eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Retrieving current addons for cluster {cluster_name}")
        
        # Get list of addons
        addons_response = eks_client.list_addons(clusterName=cluster_name)
        addon_names = addons_response.get('addons', [])
        
        if not addon_names:
            logger.info(f"No addons found for cluster {cluster_name}")
            return []
        
        logger.info(f"Found {len(addon_names)} addons: {', '.join(addon_names)}")
        
        # Get detailed information for each addon
        current_addons = []
        for addon_name in addon_names:
            try:
                addon_response = eks_client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                
                addon_info = addon_response['addon']
                current_addons.append({
                    'name': addon_name,
                    'version': addon_info.get('addonVersion', 'unknown'),
                    'status': addon_info.get('status', 'unknown'),
                    'health': addon_info.get('health', {}),
                    'configuration_values': addon_info.get('configurationValues', '{}'),
                    'service_account_role_arn': addon_info.get('serviceAccountRoleArn'),
                    'tags': addon_info.get('tags', {}),
                    'created_at': addon_info.get('createdAt', '').isoformat() if addon_info.get('createdAt') else 'unknown',
                    'modified_at': addon_info.get('modifiedAt', '').isoformat() if addon_info.get('modifiedAt') else 'unknown'
                })
                
                logger.debug(f"Addon {addon_name}: version {addon_info.get('addonVersion', 'unknown')}, status {addon_info.get('status', 'unknown')}")
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                logger.warning(f"Failed to describe addon {addon_name}: {error_code}")
                
                current_addons.append({
                    'name': addon_name,
                    'version': 'unknown',
                    'status': 'unknown',
                    'error': f"Failed to describe: {error_code}"
                })
        
        logger.info(f"Retrieved details for {len(current_addons)} addons")
        return current_addons
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to get current addons: {error_code} - {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            raise EKSAddonUpdateError(f"EKS cluster {cluster_name} not found in region {region}")
        elif error_code == 'AccessDenied':
            raise EKSAddonUpdateError(f"Access denied to EKS cluster {cluster_name}: {error_message}")
        else:
            raise EKSAddonUpdateError(f"Failed to list addons [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=2, base_delay=3.0)
def get_addon_versions(credentials: Dict[str, str], region: str, addon_name: str, kubernetes_version: str) -> List[Dict[str, Any]]:
    """Get available addon versions for specific Kubernetes version"""
    
    try:
        eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Getting available versions for addon {addon_name} with Kubernetes {kubernetes_version}")
        
        response = eks_client.describe_addon_versions(
            kubernetesVersion=kubernetes_version,
            addonName=addon_name
        )
        
        addon_versions = response.get('addons', [])
        if not addon_versions:
            raise EKSAddonUpdateError(f"No versions found for addon {addon_name} with Kubernetes {kubernetes_version}")
        
        versions = addon_versions[0].get('addonVersions', [])
        if not versions:
            raise EKSAddonUpdateError(f"No addon versions available for {addon_name}")
        
        logger.info(f"Found {len(versions)} available versions for addon {addon_name}")
        
        # Sort versions by compatibility (most recent first)
        sorted_versions = sorted(versions, key=lambda x: x.get('addonVersion', ''), reverse=True)
        
        return sorted_versions
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to get addon versions: {error_code} - {error_message}")
        
        if error_code == 'InvalidParameterException':
            raise EKSAddonUpdateError(f"Invalid parameters for addon version query: {error_message}")
        else:
            raise EKSAddonUpdateError(f"Failed to describe addon versions [{error_code}]: {error_message}")

@retry_with_backoff(max_retries=2, base_delay=5.0)
def update_addon(
    credentials: Dict[str, str],
    region: str,
    cluster_name: str,
    addon_name: str,
    target_version: str,
    resolve_conflicts: str,
    service_account_role_arn: Optional[str] = None
) -> Dict[str, Any]:
    """Update individual addon with comprehensive error handling"""
    
    try:
        eks_client = boto3.client(
            'eks',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Updating addon {addon_name} to version {target_version}")
        
        # Prepare update parameters
        update_params = {
            'clusterName': cluster_name,
            'addonName': addon_name,
            'addonVersion': target_version,
            'resolveConflicts': resolve_conflicts
        }
        
        # Add service account role if provided
        if service_account_role_arn:
            update_params['serviceAccountRoleArn'] = service_account_role_arn
        
        response = eks_client.update_addon(**update_params)
        
        update_info = response.get('update', {})
        
        result = {
            'addon': addon_name,
            'target_version': target_version,
            'update_id': update_info.get('id', 'unknown'),
            'status': update_info.get('status', 'unknown'),
            'type': update_info.get('type', 'unknown'),
            'created_at': update_info.get('createdAt', '').isoformat() if update_info.get('createdAt') else 'unknown',
            'resolve_conflicts': resolve_conflicts,
            'success': True
        }
        
        logger.info(f"Successfully initiated update for addon {addon_name}: update ID {result['update_id']}")
        
        return result
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Failed to update addon {addon_name}: {error_code} - {error_message}")
        
        # Determine if error is retryable
        retryable_codes = ['ServiceUnavailableException', 'ThrottlingException']
        is_retryable = error_code in retryable_codes
        
        result = {
            'addon': addon_name,
            'target_version': target_version,
            'success': False,
            'error': error_message,
            'error_code': error_code,
            'retryable': is_retryable
        }
        
        if error_code == 'ResourceInUseException':
            result['error'] = f"Addon {addon_name} is already being updated"
        elif error_code == 'InvalidParameterException':
            result['error'] = f"Invalid parameters for addon {addon_name}: {error_message}"
        elif error_code == 'InvalidRequestException':
            result['error'] = f"Invalid update request for addon {addon_name}: {error_message}"
        
        return result

def analyze_update_compatibility(
    current_addon: Dict[str, Any],
    target_version: str,
    available_versions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Analyze addon update compatibility and risks"""
    
    addon_name = current_addon['name']
    current_version = current_addon.get('version', 'unknown')
    
    # Find target version in available versions
    target_version_info = None
    for version_info in available_versions:
        if version_info.get('addonVersion') == target_version:
            target_version_info = version_info
            break
    
    compatibility_analysis = {
        'addon_name': addon_name,
        'current_version': current_version,
        'target_version': target_version,
        'compatible': target_version_info is not None,
        'risks': [],
        'recommendations': []
    }
    
    if not target_version_info:
        compatibility_analysis['risks'].append(f"Target version {target_version} not available for addon {addon_name}")
        compatibility_analysis['recommendations'].append("Use latest compatible version instead")
        return compatibility_analysis
    
    # Check for breaking changes
    compatibilities = target_version_info.get('compatibilities', [])
    if not compatibilities:
        compatibility_analysis['risks'].append("No compatibility information available")
    
    # Check if it's a major version upgrade
    try:
        if current_version != 'unknown':
            current_major = int(current_version.split('.')[0]) if '.' in current_version else 0
            target_major = int(target_version.split('.')[0]) if '.' in target_version else 0
            
            if target_major > current_major:
                compatibility_analysis['risks'].append("Major version upgrade - may include breaking changes")
                compatibility_analysis['recommendations'].append("Review release notes and test in non-production first")
    except (ValueError, IndexError):
        compatibility_analysis['risks'].append("Unable to parse version numbers for comparison")
    
    # Add general recommendations
    if current_addon.get('status') != 'ACTIVE':
        compatibility_analysis['risks'].append(f"Current addon status is {current_addon.get('status')}")
        compatibility_analysis['recommendations'].append("Ensure addon is in ACTIVE state before updating")
    
    if not compatibility_analysis['recommendations']:
        compatibility_analysis['recommendations'].append("Update appears safe to proceed")
    
    return compatibility_analysis

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced EKS addon update handler with comprehensive validation and monitoring
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting EKS addon update with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        role_arn = validated_data['role_arn']
        region = validated_data['region']
        cluster_name = validated_data['cluster_name']
        target_version = validated_data['target_version']
        resolve_conflicts = validated_data['resolve_conflicts']
        service_account_role_arn = validated_data['service_account_role_arn']
        execution_id = validated_data['execution_id']
        
        logger.info(f"Updating addons for cluster {cluster_name} to Kubernetes {target_version}")
        
        # Assume role in target account
        credentials = assume_cross_account_role(role_arn, 'EKSAddonUpdate')
        
        # Get current addons
        current_addons = get_current_addons(credentials, region, cluster_name)
        
        if not current_addons:
            logger.info(f"No addons found for cluster {cluster_name}")
            execution_time = time.time() - start_time
            
            return {
                'statusCode': 200,
                'updated': [],
                'skipped': [],
                'failed': [],
                'summary': {
                    'total_addons': 0,
                    'successful_updates': 0,
                    'failed_updates': 0,
                    'skipped_updates': 0
                },
                'cluster_name': cluster_name,
                'target_version': target_version,
                'execution_id': execution_id,
                'execution_time_ms': round(execution_time * 1000, 2),
                'timestamp': time.time()
            }
        
        updated_addons = []
        skipped_addons = []
        failed_addons = []
        
        # Process each addon
        for current_addon in current_addons:
            addon_name = current_addon['name']
            current_version = current_addon.get('version', 'unknown')
            current_status = current_addon.get('status', 'unknown')
            
            try:
                # Skip if addon is not in a stable state
                if current_status not in ['ACTIVE', 'DEGRADED']:
                    logger.warning(f"Skipping addon {addon_name} due to status: {current_status}")
                    skipped_addons.append({
                        'addon': addon_name,
                        'current_version': current_version,
                        'reason': f'Addon status is {current_status}, expected ACTIVE or DEGRADED'
                    })
                    continue
                
                # Get available versions for this addon
                try:
                    available_versions = get_addon_versions(credentials, region, addon_name, target_version)
                    latest_version = available_versions[0].get('addonVersion') if available_versions else None
                    
                    if not latest_version:
                        logger.warning(f"No compatible version found for addon {addon_name}")
                        skipped_addons.append({
                            'addon': addon_name,
                            'current_version': current_version,
                            'reason': f'No compatible version for Kubernetes {target_version}'
                        })
                        continue
                    
                except Exception as version_error:
                    logger.error(f"Failed to get versions for addon {addon_name}: {str(version_error)}")
                    failed_addons.append({
                        'addon': addon_name,
                        'current_version': current_version,
                        'error': str(version_error),
                        'stage': 'version_lookup'
                    })
                    continue
                
                # Skip if already at latest version
                if current_version == latest_version:
                    logger.info(f"Addon {addon_name} already at latest version {latest_version}")
                    skipped_addons.append({
                        'addon': addon_name,
                        'current_version': current_version,
                        'reason': 'Already at latest version'
                    })
                    continue
                
                # Analyze update compatibility
                compatibility = analyze_update_compatibility(current_addon, latest_version, available_versions)
                
                if not compatibility['compatible']:
                    logger.warning(f"Update not compatible for addon {addon_name}")
                    skipped_addons.append({
                        'addon': addon_name,
                        'current_version': current_version,
                        'reason': 'Incompatible version',
                        'compatibility_analysis': compatibility
                    })
                    continue
                
                # Perform the update
                logger.info(f"Updating addon {addon_name} from {current_version} to {latest_version}")
                
                update_result = update_addon(
                    credentials, region, cluster_name, addon_name, latest_version,
                    resolve_conflicts, service_account_role_arn
                )
                
                if update_result['success']:
                    update_result['compatibility_analysis'] = compatibility
                    updated_addons.append(update_result)
                    logger.info(f"Successfully initiated update for addon {addon_name}")
                else:
                    failed_addons.append(update_result)
                    logger.error(f"Failed to update addon {addon_name}: {update_result.get('error', 'Unknown error')}")
                
            except Exception as addon_error:
                logger.error(f"Unexpected error processing addon {addon_name}: {str(addon_error)}")
                failed_addons.append({
                    'addon': addon_name,
                    'current_version': current_version,
                    'error': str(addon_error),
                    'error_type': type(addon_error).__name__,
                    'stage': 'addon_processing'
                })
        
        # Generate summary
        total_addons = len(current_addons)
        successful_updates = len(updated_addons)
        failed_updates = len(failed_addons)
        skipped_updates = len(skipped_addons)
        
        execution_time = time.time() - start_time
        
        result = {
            'statusCode': 200,
            'updated': updated_addons,
            'skipped': skipped_addons,
            'failed': failed_addons,
            'summary': {
                'total_addons': total_addons,
                'successful_updates': successful_updates,
                'failed_updates': failed_updates,
                'skipped_updates': skipped_updates,
                'success_rate': round((successful_updates / total_addons) * 100, 2) if total_addons > 0 else 0.0
            },
            'cluster_name': cluster_name,
            'target_version': target_version,
            'resolve_conflicts': resolve_conflicts,
            'execution_id': execution_id,
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
        
        logger.info(f"EKS addon update completed in {execution_time:.2f}s")
        logger.info(f"Results: {successful_updates} updated, {skipped_updates} skipped, {failed_updates} failed")
        
        return result
        
    except EKSAddonUpdateError as e:
        logger.error(f"EKS addon update error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'updated': [],
            'skipped': [],
            'failed': [],
            'error': str(e),
            'error_type': 'EKSAddonUpdateError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in EKS addon update handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'updated': [],
            'skipped': [],
            'failed': [],
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
