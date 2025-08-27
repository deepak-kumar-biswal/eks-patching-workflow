#############################################
# EKS Upgrade Spoke (Target Account)
#############################################

resource "aws_iam_role" "patch_exec" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{ Effect="Allow", Principal={ AWS = "arn:aws:iam::${var.orchestrator_account_id}:root" }, Action="sts:AssumeRole" }]
  })
}

# Permissions for orchestrator to call EKS updates and read cluster states
resource "aws_iam_role_policy" "eks_ops" {
  role = aws_iam_role.patch_exec.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=[
          "eks:UpdateClusterVersion","eks:DescribeCluster","eks:DescribeUpdate",
          "eks:ListAddons","eks:DescribeAddonVersions","eks:UpdateAddon"
        ], Resource="*" },
      { Effect="Allow", Action=[ "ssm:SendCommand","ssm:GetCommandInvocation" ], Resource="*" }
    ]
  })
}
