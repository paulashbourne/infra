# Managed TURN only: room signaling remains on the RetroArena coordinator.
# Supplying both regions lets ICE test geographically different relay paths.
provider "aws" {
  alias  = "turn_west"
  region = "us-west-2"
}

locals {
  turn_template = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      Channel = {
        Type = "AWS::KinesisVideo::SignalingChannel"
        Properties = {
          Name = "retroarena-turn"
          Type = "SINGLE_MASTER"
        }
      }
    }
    Outputs = { ChannelARN = { Value = { "Fn::GetAtt" = ["Channel", "Arn"] } } }
  })
}

# AWS provider v5 doesn't expose signaling channels directly.
resource "aws_cloudformation_stack" "turn_east" {
  provider      = aws.us_east_1
  name          = "retroarena-turn"
  template_body = local.turn_template
  tags          = local.common_tags
}

resource "aws_cloudformation_stack" "turn_west" {
  provider      = aws.turn_west
  name          = "retroarena-turn"
  template_body = local.turn_template
  tags          = local.common_tags
}

resource "aws_ssm_parameter" "turn_channels" {
  name = "/retroarena/turn/channels"
  type = "String"
  value = jsonencode([
    { region = "us-west-2", arn = aws_cloudformation_stack.turn_west.outputs["ChannelARN"] },
    { region = "us-east-1", arn = aws_cloudformation_stack.turn_east.outputs["ChannelARN"] },
  ])
  tags = local.common_tags
}

resource "aws_iam_role_policy" "coordinator_turn" {
  name = "retroarena-managed-turn"
  role = aws_iam_role.coordinator.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kinesisvideo:GetSignalingChannelEndpoint", "kinesisvideo:GetIceServerConfig"]
        Resource = [aws_cloudformation_stack.turn_east.outputs["ChannelARN"], aws_cloudformation_stack.turn_west.outputs["ChannelARN"]]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = aws_ssm_parameter.turn_channels.arn
      },
    ]
  })
}
