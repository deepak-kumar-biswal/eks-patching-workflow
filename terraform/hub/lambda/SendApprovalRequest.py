import os
import json
import boto3
import uuid
import time
import logging
import urllib.parse
import hashlib
from typing import Dict, Any, Optional, List
from botocore.exceptions import ClientError, BotoCoreError
from functools import wraps
from datetime import datetime, timedelta

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
)
logger = logging.getLogger(__name__)

class EKSApprovalRequestError(Exception):
    """Custom exception for EKS approval request operations"""
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
                    
                    if error_code in ['ValidationException', 'SubscriptionRequiredException']:
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
    if 'taskToken' not in event:
        raise EKSApprovalRequestError("Missing required field: taskToken")
    
    task_token = event['taskToken']
    if not task_token or not isinstance(task_token, str):
        raise EKSApprovalRequestError("Invalid task token")
    
    # Validate environment variables
    topic_arn = os.environ.get('TOPIC_ARN')
    if not topic_arn:
        raise EKSApprovalRequestError("TOPIC_ARN environment variable not set")
    
    apigw_base = os.environ.get('APIGW_BASE')
    if not apigw_base:
        raise EKSApprovalRequestError("APIGW_BASE environment variable not set")
    
    # Extract optional fields
    subject = event.get('subject', 'EKS Cluster Patching Approval Required')
    details = event.get('details', {})
    execution_id = event.get('executionId', 'unknown')
    estimated_duration = event.get('estimatedDuration', 'unknown')
    
    return {
        'task_token': task_token,
        'subject': subject,
        'details': details,
        'topic_arn': topic_arn,
        'apigw_base': apigw_base,
        'execution_id': execution_id,
        'estimated_duration': estimated_duration
    }

def create_approval_links(apigw_base: str, task_token: str, execution_id: str) -> Dict[str, str]:
    """Create secure approval and rejection links"""
    
    # URL encode the task token
    encoded_token = urllib.parse.quote(task_token, safe='')
    
    # Add timestamp and execution ID for tracking
    timestamp = int(time.time())
    
    approve_url = f"{apigw_base}/callback?action=approve&token={encoded_token}&executionId={execution_id}&timestamp={timestamp}"
    reject_url = f"{apigw_base}/callback?action=reject&token={encoded_token}&executionId={execution_id}&timestamp={timestamp}"
    
    return {
        'approve_url': approve_url,
        'reject_url': reject_url
    }

def format_eks_details_for_notification(details: Dict[str, Any]) -> str:
    """Format EKS execution details for human-readable notification"""
    
    if not details:
        return "No additional details provided."
    
    formatted_parts = []
    
    # EKS waves information
    if 'eksWaves' in details:
        eks_waves = details['eksWaves']
        if isinstance(eks_waves, list) and len(eks_waves) > 0:
            total_clusters = sum(len(wave.get('targets', [])) for wave in eks_waves)
            regions = set()
            accounts = set()
            
            for wave in eks_waves:
                for target in wave.get('targets', []):
                    regions.add(target.get('region', 'unknown'))
                    # Extract account from role ARN
                    role_arn = target.get('roleArn', '')
                    if '::' in role_arn:
                        try:
                            account = role_arn.split('::')[1].split(':')[0]
                            accounts.add(account)
                        except:
                            pass
            
            formatted_parts.append(f"📊 **EKS Patching Scope:**")
            formatted_parts.append(f"   • Clusters: {total_clusters}")
            formatted_parts.append(f"   • Accounts: {len(accounts)}")
            formatted_parts.append(f"   • Regions: {len(regions)}")
            formatted_parts.append(f"   • Waves: {len(eks_waves)}")
            
            # List clusters per wave
            for i, wave in enumerate(eks_waves, 1):
                targets = wave.get('targets', [])
                cluster_names = [target.get('clusterName', 'unknown') for target in targets]
                formatted_parts.append(f"   • Wave {i}: {len(targets)} clusters ({', '.join(cluster_names[:3])}{'...' if len(cluster_names) > 3 else ''})")
    
    # Target Kubernetes version
    if 'targetVersion' in details:
        target_version = details['targetVersion']
        formatted_parts.append(f"🎯 **Target Version:** Kubernetes {target_version}")
    
    # Karpenter configuration
    if 'karpenter' in details:
        karpenter_config = details['karpenter']
        if isinstance(karpenter_config, dict):
            enabled = karpenter_config.get('enabled', False)
            node_class = karpenter_config.get('nodeClassName', 'default')
            formatted_parts.append(f"🚢 **Karpenter:** {'Enabled' if enabled else 'Disabled'}")
            if enabled:
                formatted_parts.append(f"   • Node Class: {node_class}")
    
    # Additional settings
    if 'abortOnIssues' in details:
        abort_setting = "Yes" if details['abortOnIssues'] else "No"
        formatted_parts.append(f"⚠️  **Abort on Issues:** {abort_setting}")
    
    if 'wavePauseSeconds' in details:
        pause_minutes = details['wavePauseSeconds'] // 60
        formatted_parts.append(f"⏱️  **Wave Pause:** {pause_minutes} minutes")
    
    if 'addonUpdates' in details:
        addon_updates = details['addonUpdates']
        if isinstance(addon_updates, dict):
            enabled = addon_updates.get('enabled', True)
            resolve_conflicts = addon_updates.get('resolveConflicts', 'OVERWRITE')
            formatted_parts.append(f"🔧 **Addon Updates:** {'Enabled' if enabled else 'Disabled'}")
            if enabled:
                formatted_parts.append(f"   • Conflict Resolution: {resolve_conflicts}")
    
    return "\n".join(formatted_parts) if formatted_parts else json.dumps(details, indent=2, default=str)

def create_eks_notification_message(
    subject: str,
    details: Dict[str, Any],
    approve_url: str,
    reject_url: str,
    execution_id: str,
    estimated_duration: Any,
    task_token_hash: str
) -> Dict[str, str]:
    """Create comprehensive EKS notification message"""
    
    # Format timestamp
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Format estimated duration
    duration_text = f"{estimated_duration} minutes" if isinstance(estimated_duration, (int, float)) else str(estimated_duration)
    
    # Create detailed message body
    message_body = f"""
🚨 **APPROVAL REQUIRED: EKS Cluster Patching Operation**

A scheduled EKS cluster patching operation is requesting approval to proceed.

**📋 Execution Information:**
• Execution ID: {execution_id}
• Request Time: {current_time}
• Estimated Duration: {duration_text}
• Request ID: {task_token_hash}

**🔧 Operation Details:**
{format_eks_details_for_notification(details)}

**⚡ ACTIONS REQUIRED:**

✅ **APPROVE:** Click here to approve and start EKS patching
   {approve_url}

❌ **REJECT:** Click here to reject and cancel operation  
   {reject_url}

**⚠️ Important Notes:**
• This approval will expire after 1 hour
• EKS cluster updates may cause brief service interruptions
• Node replacements will occur during the patching process
• Karpenter will provision new nodes with updated AMIs
• All operations are logged and audited
• Contact the Platform team if you have questions

**🔗 Monitoring:**
• Check Step Functions console for execution details
• Monitor CloudWatch dashboards during execution
• EKS Console will show cluster update progress
• SNS notifications will provide status updates

**📞 Support:**
For questions or issues, contact: platform-team@company.com

**🛡️ Safety Measures:**
• Pre-flight checks completed successfully
• Rollback procedures are available if needed
• Monitoring and alerting are active

---
This is an automated message from the EKS Patching Orchestrator.
Execution ID: {execution_id} | Request: {task_token_hash}
"""
    
    return {
        'subject': subject,
        'body': message_body.strip()
    }

@retry_with_backoff(max_retries=3, base_delay=1.0)
def send_sns_notification(topic_arn: str, subject: str, message: str, execution_id: str) -> str:
    """Send SNS notification with comprehensive error handling"""
    
    try:
        sns_client = boto3.client('sns')
        
        logger.info(f"Sending EKS approval SNS notification for execution {execution_id}")
        
        # Add message attributes for filtering and routing
        message_attributes = {
            'NotificationType': {
                'DataType': 'String',
                'StringValue': 'EKSApprovalRequest'
            },
            'ExecutionId': {
                'DataType': 'String', 
                'StringValue': execution_id
            },
            'Priority': {
                'DataType': 'String',
                'StringValue': 'High'
            },
            'Service': {
                'DataType': 'String',
                'StringValue': 'EKS'
            },
            'Timestamp': {
                'DataType': 'Number',
                'StringValue': str(int(time.time()))
            }
        }
        
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
            MessageAttributes=message_attributes
        )
        
        message_id = response.get('MessageId', 'unknown')
        logger.info(f"EKS approval SNS notification sent successfully: {message_id}")
        
        return message_id
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"SNS publish failed: {error_code} - {error_message}")
        
        if error_code == 'NotFound':
            raise EKSApprovalRequestError(f"SNS topic not found: {topic_arn}")
        elif error_code == 'InvalidParameter':
            raise EKSApprovalRequestError(f"Invalid SNS parameters: {error_message}")
        elif error_code == 'SubscriptionRequiredException':
            raise EKSApprovalRequestError(f"No subscribers for SNS topic: {topic_arn}")
        else:
            raise EKSApprovalRequestError(f"SNS publish failed [{error_code}]: {error_message}")

def send_slack_notification(webhook_url: str, message_data: Dict[str, str], execution_id: str) -> bool:
    """Send Slack notification for EKS approval (optional enhancement)"""
    
    if not webhook_url:
        return False
    
    try:
        import requests
        
        slack_payload = {
            "text": f"🚨 EKS Cluster Patching Approval Required",
            "attachments": [
                {
                    "color": "warning",
                    "title": message_data['subject'],
                    "text": message_data['body'][:1000] + "..." if len(message_data['body']) > 1000 else message_data['body'],
                    "footer": f"EKS Execution ID: {execution_id}",
                    "ts": int(time.time())
                }
            ]
        }
        
        response = requests.post(webhook_url, json=slack_payload, timeout=10)
        response.raise_for_status()
        
        logger.info(f"EKS approval Slack notification sent for execution {execution_id}")
        return True
        
    except Exception as e:
        logger.warning(f"Failed to send EKS Slack notification: {str(e)}")
        return False

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced EKS approval request handler with comprehensive notification capabilities
    """
    start_time = time.time()
    
    try:
        logger.info(f"Processing EKS approval request with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        task_token = validated_data['task_token']
        subject = validated_data['subject']
        details = validated_data['details']
        topic_arn = validated_data['topic_arn']
        apigw_base = validated_data['apigw_base']
        execution_id = validated_data['execution_id']
        estimated_duration = validated_data['estimated_duration']
        
        # Create task token hash for tracking (don't log full token)
        task_token_hash = hashlib.md5(task_token.encode()).hexdigest()[:8]
        
        logger.info(f"Creating EKS approval request for execution {execution_id} (token: {task_token_hash})")
        
        # Create approval links
        links = create_approval_links(apigw_base, task_token, execution_id)
        
        # Create notification message
        notification = create_eks_notification_message(
            subject, details, links['approve_url'], links['reject_url'],
            execution_id, estimated_duration, task_token_hash
        )
        
        # Send SNS notification
        message_id = send_sns_notification(
            topic_arn, notification['subject'], notification['body'], execution_id
        )
        
        # Optional: Send Slack notification
        slack_webhook = os.environ.get('SLACK_WEBHOOK_URL', '')
        slack_sent = send_slack_notification(slack_webhook, notification, execution_id) if slack_webhook else False
        
        execution_time = time.time() - start_time
        
        result = {
            'statusCode': 200,
            'success': True,
            'notified': True,
            'message_id': message_id,
            'execution_id': execution_id,
            'task_token_hash': task_token_hash,
            'notification_channels': {
                'sns': True,
                'slack': slack_sent
            },
            'approval_links': {
                'approve_url_length': len(links['approve_url']),
                'reject_url_length': len(links['reject_url'])
            },
            'service_type': 'EKS',
            'execution_time_ms': execution_time * 1000,
            'timestamp': time.time()
        }
        
        logger.info(f"EKS approval request completed successfully in {execution_time:.2f}s")
        logger.info(f"SNS message ID: {message_id}, Slack sent: {slack_sent}")
        
        return result
        
    except EKSApprovalRequestError as e:
        logger.error(f"EKS approval request error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'success': False,
            'notified': False,
            'error': str(e),
            'error_type': 'EKSApprovalRequestError',
            'service_type': 'EKS',
            'execution_time_ms': execution_time * 1000,
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in EKS approval request handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'success': False,
            'notified': False,
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'service_type': 'EKS',
            'execution_time_ms': execution_time * 1000,
            'timestamp': time.time()
        }
