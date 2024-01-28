// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrock_test

import (
	"fmt"
	"testing"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

func TestAccBedrockCustomModelDataSource_basic(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_bedrock_custom_model.test"
	datasourceName := "data.aws_bedrock_custom_model.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomModelDataSourceConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(datasourceName, "id"),
					resource.TestCheckResourceAttrPair(resourceName, "base_model_arn", datasourceName, "base_model_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "creation_time", datasourceName, "creation_time"),
					resource.TestCheckResourceAttrPair(resourceName, "hyper_parameters", datasourceName, "hyper_parameters"),
					resource.TestCheckResourceAttrPair(resourceName, "job_arn", datasourceName, "job_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "job_name", datasourceName, "job_name"),
					resource.TestCheckResourceAttrPair(resourceName, "job_tags", datasourceName, "job_tags"),
					resource.TestCheckResourceAttrPair(resourceName, "model_arn", datasourceName, "model_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "model_kms_key_arn", datasourceName, "model_kms_key_arn"),
					resource.TestCheckResourceAttrPair(resourceName, "model_name", datasourceName, "model_name"),
					resource.TestCheckResourceAttrPair(resourceName, "output_data_config", datasourceName, "output_data_config"),
					resource.TestCheckResourceAttrPair(resourceName, "training_data_config", datasourceName, "training_data_config"),
					resource.TestCheckResourceAttrPair(resourceName, "training_metrics", datasourceName, "training_metrics"),
					resource.TestCheckResourceAttrPair(resourceName, "validation_data_config", datasourceName, "validation_data_config"),
					resource.TestCheckResourceAttrPair(resourceName, "validation_metrics", datasourceName, "validation_metrics"),
				),
			},
		},
	})
}

// TODO Shared config with resource?
func testAccCustomModelDataSourceConfig_basic(rName string) string {
	return fmt.Sprintf(`
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

resource aws_s3_bucket training_data {
  bucket = "bedrock-training-data-%[1]s"
}

resource aws_s3_bucket validation_data {
  bucket = "bedrock-validation-data-%[1]s"
}

resource aws_s3_bucket output_data {
  bucket        = "bedrock-output-data-%[1]s"
  force_destroy = true
}

resource "aws_s3_bucket_object" "training_data" {
  bucket = aws_s3_bucket.training_data.id
  key    = "myfolder/training_data.jsonl"
  source = "./testdata/training_data.jsonl"
  etag   = filemd5("./testdata/training_data.jsonl")
}

resource "aws_s3_bucket_object" "validation_data" {
  bucket = aws_s3_bucket.validation_data.id
  key    = "myfolder/validation_data.jsonl"
  source = "./testdata/validation_data.jsonl"
  etag   = filemd5("./testdata/validation_data.jsonl")
}

resource "aws_iam_role" "bedrock_fine_tuning" {
  name = "bedrock-fine-tuning-%[1]s"

  assume_role_policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": {
				"Service": "bedrock.amazonaws.com"
			},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
				},
				"ArnEquals": {
					"aws:SourceArn": "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:model-customization-job/*"
				}
			}
		}
	] 
}
EOF
}

resource "aws_iam_policy" "BedrockAccessTrainingValidationS3Policy" {
  name        = "BedrockAccessTrainingValidationS3Policy_%[1]s"
  path        = "/"
  description = "BedrockAccessTrainingValidationS3Policy"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:ListObjects"
        ],
        "Resource" : [
          "${aws_s3_bucket.training_data.arn}",
          "${aws_s3_bucket.training_data.arn}/myfolder",
          "${aws_s3_bucket.training_data.arn}/myfolder/*",
          "${aws_s3_bucket.validation_data.arn}/myfolder",
          "${aws_s3_bucket.validation_data.arn}/myfolder/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "BedrockAccessOutputS3Policy" {
  name        = "BedrockAccessOutputS3Policy_%[1]s"
  path        = "/"
  description = "BedrockAccessOutputS3Policy"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:ListObjects"
        ],
        "Resource" : [
          "${aws_s3_bucket.output_data.arn}/myfolder",
          "${aws_s3_bucket.output_data.arn}/myfolder/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_attachment_1" {
  role       = aws_iam_role.bedrock_fine_tuning.name
  policy_arn = aws_iam_policy.BedrockAccessTrainingValidationS3Policy.arn
}

resource "aws_iam_role_policy_attachment" "bedrock_attachment_2" {
  role       = aws_iam_role.bedrock_fine_tuning.name
  policy_arn = aws_iam_policy.BedrockAccessOutputS3Policy.arn
}

resource "aws_bedrock_custom_model" "test" {
  custom_model_name = %[1]q
  job_name          = %[1]q
  base_model_id     = "amazon.titan-text-express-v1"
  role_arn          = aws_iam_role.bedrock_fine_tuning.arn
  hyper_parameters = {
    "epochCount"              = "1"
    "batchSize"               = "1"
    "learningRate"            = "0.005"
    "learningRateWarmupSteps" = "0"
  }
  output_data_config   = "s3://${aws_s3_bucket.output_data.id}/myfolder/"
  training_data_config = "s3://${aws_s3_bucket.training_data.id}/myfolder/training_data.jsonl"
}

data "aws_bedrock_custom_model" "test" {
  model_id = aws_bedrock_custom_model.test.model_arn
}
`, rName)
}
