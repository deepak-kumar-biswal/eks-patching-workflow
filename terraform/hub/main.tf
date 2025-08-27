#############################################
# EKS Upgrade Orchestrator (Hub Account)
#############################################

locals {
  s3_bucket_name     = "${var.name_prefix}-${var.orchestrator_account_id}-eks-artifacts"
  sns_topic_name     = "${var.name_prefix}-ClusterAlerts"
  sfn_name           = "${var.name_prefix}-EKSUpgradeOrchestrator"
  approval_lambda    = "${var.name_prefix}-SendApprovalRequest"
  callback_lambda    = "${var.name_prefix}-ApprovalCallback"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = local.s3_bucket_name
  force_destroy = false
}

resource "aws_sns_topic" "alerts" {
  name = local.sns_topic_name
}

resource "aws_sns_topic_subscription" "emails" {
  count     = length(var.sns_email_subscriptions)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.sns_email_subscriptions[count.index]
}

# Package Lambdas
data "archive_file" "pre_eks" { type="zip", source_file="${path.module}/lambda/PreEKSCheck.py", output_path="${path.module}/lambda/PreEKSCheck.zip" }
data "archive_file" "addons"  { type="zip", source_file="${path.module}/lambda/UpdateEksAddons.py", output_path="${path.module}/lambda/UpdateEksAddons.zip" }
data "archive_file" "karp"    { type="zip", source_file="${path.module}/lambda/KarpenterRefresh.py", output_path="${path.module}/lambda/KarpenterRefresh.zip" }
data "archive_file" "post"    { type="zip", source_file="${path.module}/lambda/PostEKSVerify.py", output_path="${path.module}/lambda/PostEKSVerify.zip" }
data "archive_file" "bedrock" { type="zip", source_file="${path.module}/lambda/AnalyzeWithBedrock.py", output_path="${path.module}/lambda/AnalyzeWithBedrock.zip" }
data "archive_file" "approval"{ type="zip", source_file="${path.module}/lambda/SendApprovalRequest.py", output_path="${path.module}/lambda/SendApprovalRequest.zip" }
data "archive_file" "callback"{ type="zip", source_file="${path.module}/lambda/ApprovalCallback.py", output_path="${path.module}/lambda/ApprovalCallback.zip" }

# IAM for Lambdas
data "aws_iam_policy_document" "lambda_assume" {
  statement { actions=["sts:AssumeRole"]; principals { type="Service" identifiers=["lambda.amazonaws.com"] } }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.name_prefix}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda_permissions" {
  name = "${var.name_prefix}-lambda-permissions"
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=["s3:PutObject","s3:PutObjectAcl"], Resource="${aws_s3_bucket.artifacts.arn}/*" },
      { Effect="Allow", Action=["sns:Publish"], Resource=aws_sns_topic.alerts.arn },
      { Effect="Allow", Action=["sts:AssumeRole"], Resource="arn:aws:iam::*:role/PatchExecRole" },
      { Effect="Allow", Action=["bedrock:InvokeAgent"], Resource="*" }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_permissions_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}

# Lambdas
resource "aws_lambda_function" "pre" {
  function_name = "${var.name_prefix}-PreEKSCheck"
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.pre_eks.output_path
  source_code_hash = data.archive_file.pre_eks.output_base64sha256
  handler       = "PreEKSCheck.handler"
  runtime       = "python3.11"
  environment { variables = { S3_BUCKET = aws_s3_bucket.artifacts.bucket } }
}

resource "aws_lambda_function" "addons" {
  function_name = "${var.name_prefix}-UpdateEksAddons"
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.addons.output_path
  source_code_hash = data.archive_file.addons.output_base64sha256
  handler       = "UpdateEksAddons.handler"
  runtime       = "python3.11"
}

resource "aws_lambda_function" "karp" {
  function_name = "${var.name_prefix}-KarpenterRefresh"
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.karp.output_path
  source_code_hash = data.archive_file.karp.output_base64sha256
  handler       = "KarpenterRefresh.handler"
  runtime       = "python3.11"
}

resource "aws_lambda_function" "post" {
  function_name = "${var.name_prefix}-PostEKSVerify"
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.post.output_path
  source_code_hash = data.archive_file.post.output_base64sha256
  handler       = "PostEKSVerify.handler"
  runtime       = "python3.11"
  environment { variables = { S3_BUCKET = aws_s3_bucket.artifacts.bucket } }
}

resource "aws_lambda_function" "bedrock" {
  function_name = "${var.name_prefix}-AnalyzeWithBedrock"
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.bedrock.output_path
  source_code_hash = data.archive_file.bedrock.output_base64sha256
  handler       = "AnalyzeWithBedrock.handler"
  runtime       = "python3.11"
}

resource "aws_lambda_function" "approval" {
  function_name = local.approval_lambda
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.approval.output_path
  source_code_hash = data.archive_file.approval.output_base64sha256
  handler       = "SendApprovalRequest.handler"
  runtime       = "python3.11"
  environment {
    variables = {
      TOPIC_ARN  = aws_sns_topic.alerts.arn
      APIGW_BASE = aws_apigatewayv2_api.http_api.api_endpoint
    }
  }
}

resource "aws_lambda_function" "callback" {
  function_name = local.callback_lambda
  role          = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.callback.output_path
  source_code_hash = data.archive_file.callback.output_base64sha256
  handler       = "ApprovalCallback.handler"
  runtime       = "python3.11"
}

# API Gateway for approval callback
resource "aws_apigatewayv2_api" "http_api" {
  name          = "${var.name_prefix}-ApprovalCallbackAPI"
  protocol_type = "HTTP"
}
resource "aws_apigatewayv2_integration" "lambda_proxy" {
  api_id           = aws_apigatewayv2_api.http_api.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.callback.invoke_arn
}
resource "aws_apigatewayv2_route" "callback" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "GET /callback"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}
resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowInvokeByAPIGW"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# Step Functions
data "aws_iam_policy_document" "sfn_assume" {
  statement { actions=["sts:AssumeRole"]; principals { type="Service" identifiers=["states.amazonaws.com"] } }
}

resource "aws_iam_role" "sfn_role" {
  name               = "${var.name_prefix}-sfn-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

resource "aws_iam_role_policy" "sfn_inline" {
  role = aws_iam_role.sfn_role.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=["lambda:InvokeFunction"], Resource=[
        aws_lambda_function.pre.arn, aws_lambda_function.addons.arn,
        aws_lambda_function.karp.arn, aws_lambda_function.post.arn,
        aws_lambda_function.bedrock.arn, aws_lambda_function.approval.arn
      ]},
      { Effect="Allow", Action=["eks:UpdateClusterVersion","eks:DescribeUpdate","eks:ListAddons"], Resource="*" },
      { Effect="Allow", Action=["sns:Publish"], Resource=aws_sns_topic.alerts.arn },
      { Effect="Allow", Action=["sts:AssumeRole"], Resource="arn:aws:iam::*:role/PatchExecRole" }
    ]
  })
}

locals {
  sfn_definition = jsonencode({
    Comment = "EKS upgrade orchestrator with per-account waves and manual approval",
    StartAt = "ManualApproval",
    States = {
      ManualApproval = {
        Type = "Task",
        Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken",
        Parameters = {
          FunctionName = aws_lambda_function.approval.function_name,
          Payload = {
            taskToken.$ = "$$.Task.Token",
            subject     = "Approve EKS upgrade (per-account waves)",
            details.$   = "$"
          }
        },
        ResultPath = "$.approval",
        Next = "WaveMap"
      },
      WaveMap = {
        Type = "Map",
        ItemsPath = "$.eksWaves",
        MaxConcurrency = 1,
        Iterator = {
          StartAt = "ClusterMap",
          States = {
            ClusterMap = {
              Type = "Map",
              ItemsPath = "$.targets",
              MaxConcurrency = 1,
              Iterator = {
                StartAt = "UpdateControlPlane",
                States = {
                  UpdateControlPlane = {
                    Type = "Task",
                    Resource = "arn:aws:states:::aws-sdk:eks:updateClusterVersion",
                    Parameters = { "name.$": "$.clusterName", "kubernetesVersion.$": "$.targetVersion" },
                    Credentials = { "RoleArn.$": "$.roleArn" },
                    ResultPath = "$.cpUpdate",
                    Next = "WaitCP"
                  },
                  WaitCP = { Type = "Wait", Seconds = 30, Next = "CheckCP" },
                  CheckCP = {
                    Type = "Task",
                    Resource = "arn:aws:states:::aws-sdk:eks:describeUpdate",
                    Parameters = { "name.$": "$.clusterName", "updateId.$": "$.cpUpdate.update.id" },
                    Credentials = { "RoleArn.$": "$.roleArn" },
                    ResultPath = "$.cpStatus",
                    Next = "CPDone?"
                  },
                  CPDone? = {
                    Type = "Choice",
                    Choices = [ { Variable = "$.cpStatus.update.status", StringEquals = "Successful", Next = "UpdateAddons" } ],
                    Default = "WaitCP"
                  },
                  UpdateAddons = {
                    Type = "Task",
                    Resource = "arn:aws:states:::lambda:invoke",
                    Parameters = { "FunctionName": aws_lambda_function.addons.function_name, "Payload.$": "$" },
                    ResultPath = "$.addons",
                    Next = "RefreshKarpenterNodes"
                  },
                  RefreshKarpenterNodes = {
                    Type = "Task",
                    Resource = "arn:aws:states:::lambda:invoke",
                    Parameters = { "FunctionName": aws_lambda_function.karp.function_name, "Payload.$": "$" },
                    ResultPath = "$.nodes",
                    Next = "PostEKSVerify"
                  },
                  PostEKSVerify = {
                    Type = "Task",
                    Resource = "arn:aws:states:::lambda:invoke",
                    Parameters = { "FunctionName": aws_lambda_function.post.function_name, "Payload.$": "$" },
                    ResultPath = "$.post",
                    Next = "ClusterIssues?"
                  },
                  ClusterIssues? = {
                    Type = "Choice",
                    Choices = [ { Variable = "$.post.Payload.hasIssues", BooleanEquals = true, Next = "AnalyzeClusterIssues" } ],
                    Default = "ClusterDone"
                  },
                  AnalyzeClusterIssues = {
                    Type = "Task",
                    Resource = "arn:aws:states:::lambda:invoke",
                    Parameters = { "FunctionName": aws_lambda_function.bedrock.function_name, "Payload.$": "$" },
                    ResultPath = "$.analysis",
                    Next = "AbortOrClusterDone"
                  },
                  AbortOrClusterDone = {
                    Type = "Choice",
                    Choices = [ { Variable = "$.abortOnIssues", BooleanEquals = true, Next = "FailCluster" } ],
                    Default = "ClusterDone"
                  },
                  FailCluster = { Type = "Fail", Cause = "Issues detected; abortOnIssues == true" },
                  ClusterDone = { Type = "Succeed" }
                }
              },
              Next = "WavePause"
            },
            WavePause = { Type = "Wait", SecondsPath = "$.wavePauseSeconds", Next = "WaveDone" },
            WaveDone  = { Type = "Succeed" }
          }
        },
        Next = "Done"
      },
      Done = { Type = "Succeed" }
    }
  })
}

resource "aws_sfn_state_machine" "orchestrator" {
  name       = local.sfn_name
  role_arn   = aws_iam_role.sfn_role.arn
  definition = local.sfn_definition
}

# EventBridge per-account wave rules
resource "aws_iam_role" "events_invoke" {
  name               = "${var.name_prefix}-events-invoke-sfn"
  assume_role_policy = jsonencode({ Version="2012-10-17", Statement=[{ Effect="Allow", Principal={Service="events.amazonaws.com"}, Action="sts:AssumeRole" }] })
}
resource "aws_iam_role_policy" "events_invoke" {
  role = aws_iam_role.events_invoke.id
  policy = jsonencode({ Version="2012-10-17", Statement=[{ Effect="Allow", Action="states:StartExecution", Resource=aws_sfn_state_machine.orchestrator.arn }] })
}

resource "aws_cloudwatch_event_rule" "waves" {
  for_each            = { for w in var.wave_rules : w.name => w }
  name                = "${var.name_prefix}-${each.value.name}"
  description         = "Wave rule ${each.value.name}"
  schedule_expression = each.value.schedule_expression
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "waves" {
  for_each  = aws_cloudwatch_event_rule.waves
  rule      = each.value.name
  target_id = "sfn"
  arn       = aws_sfn_state_machine.orchestrator.arn
  role_arn  = aws_iam_role.events_invoke.arn
  input     = jsonencode({
    eksWaves          = [ { targets = [ for a in each.value.accounts : {
                          clusterName       = "REPLACE_ME",   # customize per wave
                          region            = each.value.regions[0],
                          targetVersion     = "1.29",
                          roleArn           = "arn:aws:iam::${a}:role/PatchExecRole",
                          controllerInstanceId = "i-REPLACE"
                        } ],
                        wavePauseSeconds = var.wave_pause_seconds,
                        abortOnIssues    = var.abort_on_issues } ],
    snsTopicArn  = aws_sns_topic.alerts.arn,
    bedrock      = { agentId = var.bedrock_agent_id, agentAliasId = var.bedrock_agent_alias_id }
  })
}

# CloudWatch dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        "type":"metric","x":0,"y":0,"width":12,"height":6,
        "properties":{
          "metrics":[ ["AWS/States","ExecutionsStarted","StateMachineArn", aws_sfn_state_machine.orchestrator.arn],
                      ["AWS/States","ExecutionsFailed","StateMachineArn", aws_sfn_state_machine.orchestrator.arn],
                      ["AWS/States","ExecutionsSucceeded","StateMachineArn", aws_sfn_state_machine.orchestrator.arn] ],
          "view":"timeSeries","stacked":false,"region":var.region,"title":"EKS Upgrade Orchestrations"
        }
      },
      {
        "type":"metric","x":12,"y":0,"width":12,"height":6,
        "properties":{
          "metrics":[ ["AWS/Lambda","Errors","FunctionName", aws_lambda_function.pre.function_name],
                      ["AWS/Lambda","Errors","FunctionName", aws_lambda_function.post.function_name],
                      ["AWS/Lambda","Errors","FunctionName", aws_lambda_function.addons.function_name] ],
          "view":"timeSeries","stacked":false,"region":var.region,"title":"Lambda Errors"
        }
      }
    ]
  })
}
