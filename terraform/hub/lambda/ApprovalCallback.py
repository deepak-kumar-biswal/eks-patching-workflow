"""
EKS Approval Callback Lambda Function
Production-grade AWS Lambda function for handling EKS patching workflow approval callbacks.
Processes approval/rejection decisions from notification systems and updates Step Functions execution.
"""

import json
import logging
import os
import time
import boto3
import urllib.parse
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError
from functools import wraps
from typing import Dict, Any, Optional, Tuple

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Remove default handler and add custom formatter
if logger.handlers:
    for handler in logger.handlers:
        logger.removeHandler(handler)

handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Global clients with explicit configuration
try:
    sf_client = boto3.client(
        'stepfunctions',
        region_name=os.environ.get('AWS_REGION', 'us-east-1'),
        config=boto3.session.Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            read_timeout=60
        )
    )
    s3_client = boto3.client(
        's3',
        region_name=os.environ.get('AWS_REGION', 'us-east-1'),
        config=boto3.session.Config(
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            read_timeout=60
        )
    )
except Exception as e:
    logger.error(f"Failed to initialize AWS clients: {str(e)}")
    raise

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """
    Decorator to retry function calls on failure with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            correlation_id = kwargs.get('correlation_id', 'unknown')
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        logger.error(
                            f"[{correlation_id}] Function {func.__name__} failed after {max_retries} retries: {str(e)}",
                            extra={
                                'correlation_id': correlation_id,
                                'function': func.__name__,
                                'attempt': attempt + 1,
                                'error': str(e)
                            }
                        )
                        raise
                    
                    wait_time = delay * (2 ** attempt)
                    logger.warning(
                        f"[{correlation_id}] Function {func.__name__} attempt {attempt + 1} failed: {str(e)}. Retrying in {wait_time}s",
                        extra={
                            'correlation_id': correlation_id,
                            'function': func.__name__,
                            'attempt': attempt + 1,
                            'error': str(e),
                            'wait_time': wait_time
                        }
                    )
                    time.sleep(wait_time)
            
        return wrapper
    return decorator

def validate_input(event: Dict[str, Any], correlation_id: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate input event and extract required parameters.
    
    Args:
        event: Lambda event object
        correlation_id: Correlation ID for logging
        
    Returns:
        Tuple of (is_valid, error_message, parsed_params)
    """
    try:
        logger.info(f"[{correlation_id}] Validating input event", extra={
            'correlation_id': correlation_id,
            'event_keys': list(event.keys()) if event else []
        })
        
        if not isinstance(event, dict):
            return False, "Event must be a dictionary", {}
        
        # Extract query string parameters
        query_params = event.get('queryStringParameters') or {}
        if not isinstance(query_params, dict):
            return False, "queryStringParameters must be a dictionary", {}
        
        # Extract required parameters
        action = query_params.get('action', '').lower().strip()
        token = query_params.get('token', '').strip()
        
        # Validate action
        if not action:
            return False, "Missing 'action' parameter", {}
        
        if action not in ['approve', 'reject']:
            return False, f"Invalid action '{action}'. Must be 'approve' or 'reject'", {}
        
        # Validate token
        if not token:
            return False, "Missing 'token' parameter", {}
        
        if len(token) < 10:  # Basic token length validation
            return False, "Invalid token format", {}
        
        # Extract optional parameters
        cluster = query_params.get('cluster', '')
        wave = query_params.get('wave', '')
        requester = query_params.get('requester', '')
        
        parsed_params = {
            'action': action,
            'token': token,
            'cluster': cluster,
            'wave': wave,
            'requester': requester,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
        }
        
        logger.info(f"[{correlation_id}] Input validation successful", extra={
            'correlation_id': correlation_id,
            'action': action,
            'has_token': bool(token),
            'cluster': cluster,
            'wave': wave,
            'requester': requester
        })
        
        return True, "", parsed_params
        
    except Exception as e:
        logger.error(f"[{correlation_id}] Input validation failed: {str(e)}", extra={
            'correlation_id': correlation_id,
            'error': str(e),
            'event': str(event)[:500] if event else None
        })
        return False, f"Validation error: {str(e)}", {}

@retry_on_failure(max_retries=3, delay=1.0)
def process_approval_action(params: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
    """
    Process approval or rejection action by updating Step Functions task.
    
    Args:
        params: Parsed parameters dictionary
        correlation_id: Correlation ID for logging
        
    Returns:
        Processing result dictionary
    """
    try:
        action = params['action']
        token = params['token']
        
        logger.info(f"[{correlation_id}] Processing {action} action", extra={
            'correlation_id': correlation_id,
            'action': action,
            'cluster': params.get('cluster', ''),
            'wave': params.get('wave', ''),
            'requester': params.get('requester', '')
        })
        
        if action == 'approve':
            # Prepare approval output
            output_data = {
                'approved': True,
                'action': action,
                'timestamp': params['timestamp'],
                'cluster': params.get('cluster', ''),
                'wave': params.get('wave', ''),
                'requester': params.get('requester', ''),
                'source_ip': params.get('source_ip', ''),
                'correlation_id': correlation_id
            }
            
            # Send task success to Step Functions
            response = sf_client.send_task_success(
                taskToken=token,
                output=json.dumps(output_data)
            )
            
            logger.info(f"[{correlation_id}] Approval sent successfully", extra={
                'correlation_id': correlation_id,
                'cluster': params.get('cluster', ''),
                'wave': params.get('wave', ''),
                'requester': params.get('requester', ''),
                'response': response
            })
            
            return {
                'success': True,
                'action': action,
                'message': 'EKS patching workflow approved. State machine will continue execution.',
                'details': {
                    'cluster': params.get('cluster', ''),
                    'wave': params.get('wave', ''),
                    'timestamp': params['timestamp'],
                    'correlation_id': correlation_id
                }
            }
            
        else:  # reject
            # Send task failure to Step Functions
            error_cause = {
                'reason': 'Operator rejected EKS patching workflow',
                'action': action,
                'timestamp': params['timestamp'],
                'cluster': params.get('cluster', ''),
                'wave': params.get('wave', ''),
                'requester': params.get('requester', ''),
                'source_ip': params.get('source_ip', ''),
                'correlation_id': correlation_id
            }
            
            response = sf_client.send_task_failure(
                taskToken=token,
                error='EKS_PATCHING_REJECTED',
                cause=json.dumps(error_cause)
            )
            
            logger.warning(f"[{correlation_id}] Workflow rejected", extra={
                'correlation_id': correlation_id,
                'cluster': params.get('cluster', ''),
                'wave': params.get('wave', ''),
                'requester': params.get('requester', ''),
                'response': response
            })
            
            return {
                'success': True,
                'action': action,
                'message': 'EKS patching workflow rejected. State machine execution terminated.',
                'details': {
                    'cluster': params.get('cluster', ''),
                    'wave': params.get('wave', ''),
                    'timestamp': params['timestamp'],
                    'correlation_id': correlation_id
                }
            }
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"[{correlation_id}] AWS API error processing {action}: {error_code} - {error_message}", extra={
            'correlation_id': correlation_id,
            'action': action,
            'error_code': error_code,
            'error_message': error_message,
            'aws_request_id': e.response.get('ResponseMetadata', {}).get('RequestId')
        })
        raise
        
    except Exception as e:
        logger.error(f"[{correlation_id}] Unexpected error processing {action}: {str(e)}", extra={
            'correlation_id': correlation_id,
            'action': action,
            'error': str(e)
        })
        raise

@retry_on_failure(max_retries=2, delay=0.5)
def log_approval_audit(params: Dict[str, Any], result: Dict[str, Any], correlation_id: str) -> None:
    """
    Log approval action for audit purposes.
    
    Args:
        params: Processing parameters
        result: Processing result
        correlation_id: Correlation ID for logging
    """
    try:
        # Prepare audit log entry
        audit_entry = {
            'timestamp': params['timestamp'],
            'correlation_id': correlation_id,
            'action': params['action'],
            'cluster': params.get('cluster', ''),
            'wave': params.get('wave', ''),
            'requester': params.get('requester', ''),
            'source_ip': params.get('source_ip', ''),
            'success': result['success'],
            'message': result['message'],
            'aws_request_id': result.get('aws_request_id'),
            'processing_time_ms': result.get('processing_time_ms', 0)
        }
        
        # Log to CloudWatch
        logger.info(f"[{correlation_id}] AUDIT: EKS approval callback", extra=audit_entry)
        
        # Optionally store to S3 for long-term audit retention
        bucket = os.environ.get('AUDIT_BUCKET')
        if bucket:
            try:
                audit_key = f"eks-approval-audit/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{correlation_id}.json"
                s3_client.put_object(
                    Bucket=bucket,
                    Key=audit_key,
                    Body=json.dumps(audit_entry, indent=2),
                    ContentType='application/json',
                    ServerSideEncryption='AES256'
                )
                logger.debug(f"[{correlation_id}] Audit entry stored to S3: {audit_key}")
            except Exception as s3_error:
                logger.warning(f"[{correlation_id}] Failed to store audit to S3: {str(s3_error)}")
                
    except Exception as e:
        logger.warning(f"[{correlation_id}] Failed to log audit entry: {str(e)}")

def create_response(status_code: int, message: str, details: Optional[Dict[str, Any]] = None, correlation_id: str = '') -> Dict[str, Any]:
    """
    Create standardized HTTP response.
    
    Args:
        status_code: HTTP status code
        message: Response message
        details: Optional additional details
        correlation_id: Correlation ID for logging
        
    Returns:
        HTTP response dictionary
    """
    response_body = {
        'message': message,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'correlation_id': correlation_id
    }
    
    if details:
        response_body['details'] = details
    
    # Add CORS headers for browser compatibility
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    }
    
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps(response_body, indent=2)
    }

def handler(event, context):
    """
    Main Lambda handler for EKS approval callbacks.
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        HTTP response dictionary
    """
    # Generate correlation ID for request tracking
    correlation_id = f"eks-approval-{int(time.time() * 1000)}-{context.aws_request_id[:8]}"
    start_time = time.time()
    
    logger.info(f"[{correlation_id}] EKS approval callback started", extra={
        'correlation_id': correlation_id,
        'function_name': context.function_name,
        'function_version': context.function_version,
        'aws_request_id': context.aws_request_id,
        'memory_limit': context.memory_limit_in_mb,
        'remaining_time': context.get_remaining_time_in_millis()
    })
    
    try:
        # Handle OPTIONS request for CORS preflight
        if event.get('httpMethod') == 'OPTIONS':
            logger.info(f"[{correlation_id}] Handling CORS preflight request")
            return create_response(200, "CORS preflight successful", correlation_id=correlation_id)
        
        # Validate input
        is_valid, validation_error, params = validate_input(event, correlation_id)
        if not is_valid:
            logger.warning(f"[{correlation_id}] Input validation failed: {validation_error}")
            return create_response(400, f"Invalid request: {validation_error}", correlation_id=correlation_id)
        
        # Process approval action
        result = process_approval_action(params, correlation_id=correlation_id)
        
        # Calculate processing time
        processing_time_ms = int((time.time() - start_time) * 1000)
        result['processing_time_ms'] = processing_time_ms
        
        # Log audit entry
        log_approval_audit(params, result, correlation_id)
        
        # Create success response
        status_code = 200
        response = create_response(
            status_code=status_code,
            message=result['message'],
            details=result['details'],
            correlation_id=correlation_id
        )
        
        logger.info(f"[{correlation_id}] EKS approval callback completed successfully", extra={
            'correlation_id': correlation_id,
            'action': params['action'],
            'cluster': params.get('cluster', ''),
            'wave': params.get('wave', ''),
            'processing_time_ms': processing_time_ms,
            'status_code': status_code
        })
        
        return response
        
    except Exception as e:
        processing_time_ms = int((time.time() - start_time) * 1000)
        
        logger.error(f"[{correlation_id}] EKS approval callback failed: {str(e)}", extra={
            'correlation_id': correlation_id,
            'error': str(e),
            'processing_time_ms': processing_time_ms,
            'event': str(event)[:500] if event else None
        })
        
        return create_response(
            status_code=500,
            message="Internal server error processing approval callback",
            details={'error': 'Please contact support if this issue persists'},
            correlation_id=correlation_id
        )
