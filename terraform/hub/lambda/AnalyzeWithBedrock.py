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

class BedrockAnalysisError(Exception):
    """Custom exception for Bedrock analysis operations"""
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
    
    # Extract Bedrock configuration
    bedrock_config = event.get('bedrock', {})
    
    # Get agent ID and alias ID from config or environment
    agent_id = bedrock_config.get('agentId') or os.environ.get('BEDROCK_AGENT_ID')
    alias_id = bedrock_config.get('agentAliasId') or os.environ.get('BEDROCK_AGENT_ALIAS_ID')
    
    if not agent_id:
        raise BedrockAnalysisError("BEDROCK_AGENT_ID not found in event config or environment variables")
    
    if not alias_id:
        raise BedrockAnalysisError("BEDROCK_AGENT_ALIAS_ID not found in event config or environment variables")
    
    # Extract issues from various possible locations in the event
    issues_data = None
    issue_source = 'unknown'
    
    # Check for EKS-specific post-verification issues
    if 'postEks' in event and isinstance(event['postEks'], dict):
        payload = event['postEks'].get('Payload', event['postEks'])
        if isinstance(payload, dict) and 'issues' in payload:
            issues_data = payload['issues']
            issue_source = 'postEks'
    
    # Check for generic post verification issues
    elif 'post' in event and isinstance(event['post'], dict):
        payload = event['post'].get('Payload', event['post'])
        if isinstance(payload, dict) and 'issues' in payload:
            issues_data = payload['issues']
            issue_source = 'post'
    
    # Check for EC2-specific post verification issues
    elif 'postEc2' in event and isinstance(event['postEc2'], dict):
        payload = event['postEc2'].get('Payload', event['postEc2'])
        if isinstance(payload, dict) and 'issues' in payload:
            issues_data = payload['issues']
            issue_source = 'postEc2'
    
    # Check for direct issues in event
    elif 'issues' in event:
        issues_data = event['issues']
        issue_source = 'direct'
    
    # Check for verification results
    elif 'verification_results' in event:
        issues_data = event['verification_results']
        issue_source = 'verification_results'
    
    execution_id = event.get('executionId', f'bedrock-analysis-{int(time.time())}')
    analysis_type = event.get('analysisType', 'patching_issues')
    
    return {
        'agent_id': agent_id,
        'alias_id': alias_id,
        'issues_data': issues_data,
        'issue_source': issue_source,
        'execution_id': execution_id,
        'analysis_type': analysis_type,
        'original_event': event  # Keep for context
    }

def prepare_analysis_prompt(
    issues_data: Any,
    issue_source: str,
    analysis_type: str,
    execution_id: str
) -> str:
    """Prepare comprehensive analysis prompt for Bedrock"""
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Base prompt with SRE context
    base_prompt = f"""You are a Senior Site Reliability Engineer (SRE) specializing in Kubernetes and AWS EKS cluster operations, patching, and incident response. You have extensive experience with:

- EKS cluster lifecycle management and troubleshooting
- Kubernetes addon management and compatibility issues  
- Node group health, scaling, and AMI management
- Karpenter configuration and node provisioning
- AWS service integrations and cross-account operations
- Production incident analysis and root cause analysis

**Current Analysis Request:**
- Execution ID: {execution_id}
- Analysis Type: {analysis_type}
- Timestamp: {timestamp}
- Issue Source: {issue_source}

**Your Task:**
Analyze the provided data and deliver a comprehensive technical assessment with:

1. **Executive Summary** - Brief overview of findings
2. **Technical Analysis** - Detailed breakdown of issues and patterns
3. **Root Cause Assessment** - Likely underlying causes
4. **Risk Assessment** - Impact and urgency evaluation
5. **Recommended Actions** - Prioritized remediation steps
6. **Prevention Measures** - How to avoid similar issues

**Data to Analyze:**
"""
    
    # Add specific analysis context based on type and source
    if analysis_type == 'patching_issues':
        context_prompt = """
**EKS Patching Context:**
You are analyzing issues that occurred during or after an EKS cluster patching operation. This may include:
- Cluster version upgrade problems
- Addon compatibility issues
- Node group update failures
- Karpenter configuration problems
- Application connectivity issues
- Performance degradation

Focus on patching-specific root causes and provide actionable remediation steps.
"""
    else:
        context_prompt = """
**General EKS Operations Context:**
You are analyzing operational issues in an EKS environment. Provide comprehensive analysis
covering infrastructure, applications, and operational aspects.
"""
    
    # Format the issues data
    if issues_data is None:
        data_section = "No specific issues data provided. Please provide general EKS health assessment and best practices."
    else:
        try:
            formatted_data = json.dumps(issues_data, indent=2, default=str)
            data_section = f"```json\n{formatted_data}\n```"
        except Exception as e:
            data_section = f"Raw data: {str(issues_data)}\n\nNote: Data formatting error: {str(e)}"
    
    # Combine all parts
    full_prompt = f"{base_prompt}{context_prompt}\n{data_section}\n\n**Instructions:**\nProvide a detailed technical analysis in markdown format with clear sections and actionable recommendations. Focus on production-ready solutions and include monitoring/validation steps."
    
    logger.info(f"Prepared analysis prompt: {len(full_prompt)} characters")
    
    return full_prompt

@retry_with_backoff(max_retries=3, base_delay=3.0)
def invoke_bedrock_agent(
    agent_id: str,
    alias_id: str,
    prompt: str,
    session_id: str
) -> Dict[str, Any]:
    """Invoke Bedrock agent with comprehensive error handling"""
    
    try:
        bedrock_client = boto3.client('bedrock-agent-runtime')
        
        logger.info(f"Invoking Bedrock agent {agent_id} with alias {alias_id}")
        
        response = bedrock_client.invoke_agent(
            agentId=agent_id,
            agentAliasId=alias_id,
            sessionId=session_id,
            inputText=prompt
        )
        
        # Process the response stream
        chunks = []
        chunk_count = 0
        
        for event in response.get('completion', []):
            if 'chunk' in event:
                chunk_data = event['chunk']
                if 'bytes' in chunk_data:
                    try:
                        chunk_text = chunk_data['bytes'].decode('utf-8')
                        chunks.append(chunk_text)
                        chunk_count += 1
                    except Exception as decode_error:
                        logger.warning(f"Failed to decode chunk: {decode_error}")
            elif 'content' in event:
                # Handle alternative response format
                chunks.append(str(event['content']))
                chunk_count += 1
        
        # Combine all chunks
        full_response = "".join(chunks)
        
        if not full_response.strip():
            full_response = "Bedrock agent completed processing but returned empty response. Check agent traces for details."
        
        result = {
            'response': full_response,
            'chunk_count': chunk_count,
            'response_length': len(full_response),
            'session_id': session_id,
            'agent_id': agent_id,
            'success': True
        }
        
        logger.info(f"Bedrock agent responded with {chunk_count} chunks, {len(full_response)} characters")
        
        return result
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        logger.error(f"Bedrock agent invocation failed: {error_code} - {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            raise BedrockAnalysisError(f"Bedrock agent not found: {agent_id}/{alias_id}")
        elif error_code == 'AccessDeniedException':
            raise BedrockAnalysisError(f"Access denied to Bedrock agent: {error_message}")
        elif error_code == 'ThrottlingException':
            raise BedrockAnalysisError(f"Bedrock API throttling: {error_message}")
        elif error_code == 'ValidationException':
            raise BedrockAnalysisError(f"Invalid Bedrock request: {error_message}")
        else:
            raise BedrockAnalysisError(f"Bedrock invocation failed [{error_code}]: {error_message}")

def parse_bedrock_response(response_text: str) -> Dict[str, Any]:
    """Parse and structure the Bedrock response"""
    
    # Initialize parsed sections
    parsed_sections = {
        'executive_summary': '',
        'technical_analysis': '',
        'root_cause_assessment': '',
        'risk_assessment': '',
        'recommended_actions': [],
        'prevention_measures': [],
        'full_response': response_text
    }
    
    try:
        # Split response into lines for parsing
        lines = response_text.split('\n')
        current_section = None
        current_content = []
        
        section_keywords = {
            'executive summary': 'executive_summary',
            'technical analysis': 'technical_analysis',
            'root cause': 'root_cause_assessment',
            'risk assessment': 'risk_assessment',
            'recommended actions': 'recommended_actions',
            'prevention measures': 'prevention_measures'
        }
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check if line is a section header
            section_found = None
            for keyword, section_key in section_keywords.items():
                if keyword in line_lower and ('##' in line or '**' in line or line.endswith(':')):
                    section_found = section_key
                    break
            
            if section_found:
                # Save previous section
                if current_section and current_content:
                    content = '\n'.join(current_content).strip()
                    if current_section in ['recommended_actions', 'prevention_measures']:
                        # Parse as list items
                        items = [item.strip('- •*') for item in content.split('\n') if item.strip() and item.strip().startswith(('- ', '• ', '* '))]
                        parsed_sections[current_section] = items
                    else:
                        parsed_sections[current_section] = content
                
                # Start new section
                current_section = section_found
                current_content = []
            else:
                # Add to current section
                if current_section:
                    current_content.append(line)
        
        # Handle last section
        if current_section and current_content:
            content = '\n'.join(current_content).strip()
            if current_section in ['recommended_actions', 'prevention_measures']:
                items = [item.strip('- •*') for item in content.split('\n') if item.strip() and item.strip().startswith(('- ', '• ', '* '))]
                parsed_sections[current_section] = items
            else:
                parsed_sections[current_section] = content
    
    except Exception as e:
        logger.warning(f"Failed to parse Bedrock response structure: {str(e)}")
        # Return basic structure with full response
        parsed_sections['executive_summary'] = "Response parsing failed - see full response"
    
    return parsed_sections

@with_correlation_id
def handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Enhanced Bedrock analysis handler for EKS patching and operational issues
    """
    start_time = time.time()
    
    try:
        logger.info(f"Starting Bedrock analysis with event keys: {list(event.keys())}")
        
        # Validate input
        validated_data = validate_input(event)
        
        agent_id = validated_data['agent_id']
        alias_id = validated_data['alias_id']
        issues_data = validated_data['issues_data']
        issue_source = validated_data['issue_source']
        execution_id = validated_data['execution_id']
        analysis_type = validated_data['analysis_type']
        
        logger.info(f"Analyzing {issue_source} issues with Bedrock agent {agent_id}")
        
        # Prepare analysis prompt
        analysis_prompt = prepare_analysis_prompt(
            issues_data, issue_source, analysis_type, execution_id
        )
        
        # Generate unique session ID
        session_id = f"eks-analysis-{execution_id}-{int(time.time())}"
        
        # Invoke Bedrock agent
        bedrock_result = invoke_bedrock_agent(
            agent_id, alias_id, analysis_prompt, session_id
        )
        
        # Parse the response
        parsed_analysis = parse_bedrock_response(bedrock_result['response'])
        
        execution_time = time.time() - start_time
        
        result = {
            'statusCode': 200,
            'message': bedrock_result['response'],
            'analysis': parsed_analysis,
            'metadata': {
                'execution_id': execution_id,
                'session_id': session_id,
                'agent_id': agent_id,
                'alias_id': alias_id,
                'issue_source': issue_source,
                'analysis_type': analysis_type,
                'response_stats': {
                    'chunk_count': bedrock_result['chunk_count'],
                    'response_length': bedrock_result['response_length']
                }
            },
            'recommendations_summary': parsed_analysis.get('recommended_actions', [])[:5],  # Top 5 recommendations
            'risk_level': 'high' if any(keyword in bedrock_result['response'].lower() 
                                      for keyword in ['critical', 'urgent', 'immediate', 'failure']) else 'medium',
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
        
        logger.info(f"Bedrock analysis completed in {execution_time:.2f}s")
        logger.info(f"Generated {len(parsed_analysis.get('recommended_actions', []))} recommendations")
        
        return result
        
    except BedrockAnalysisError as e:
        logger.error(f"Bedrock analysis error: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 400,
            'message': f"Analysis failed: {str(e)}",
            'error': str(e),
            'error_type': 'BedrockAnalysisError',
            'fallback_message': "Bedrock analysis unavailable. Review issues manually and consult EKS troubleshooting guides.",
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in Bedrock analysis handler: {str(e)}")
        execution_time = time.time() - start_time
        
        return {
            'statusCode': 500,
            'message': f"Unexpected analysis error: {str(e)}",
            'error': f"Unexpected error: {str(e)}",
            'error_type': 'UnexpectedError',
            'fallback_message': "Analysis service unavailable. Proceed with manual issue investigation.",
            'execution_time_ms': round(execution_time * 1000, 2),
            'timestamp': time.time()
        }
