import os, json, boto3
brt = boto3.client('bedrock-agent-runtime')

def handler(event, ctx):
    cfg = event.get('bedrock') or {}
    agent_id = cfg.get('agentId') or os.environ.get('BEDROCK_AGENT_ID')
    alias_id = cfg.get('agentAliasId') or os.environ.get('BEDROCK_AGENT_ALIAS_ID')
    issues = None
    if 'post' in event and 'Payload' in event['post']:
        issues = event['post']['Payload'].get('issues')
    elif 'postEc2' in event and 'Payload' in event['postEc2']:
        issues = event['postEc2']['Payload'].get('issues')
    prompt = ("You are a patching SRE. Analyze these discrepancies and suggest root causes & next steps.\n"
              + json.dumps(issues or {}))
    resp = brt.invoke_agent(agentId=agent_id, agentAliasId=alias_id, sessionId="run", inputText=prompt)
    chunks = []
    for c in resp.get('completion', []):
        chunks.append(c.get('content', ''))
    return {"message": "".join(chunks) or "See Bedrock Agent traces for details."}
