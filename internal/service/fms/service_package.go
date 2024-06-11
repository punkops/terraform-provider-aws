// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	awstypes "github.com/aws/aws-sdk-go-v2/service/fms/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// NewClient returns a new AWS SDK for Go v2 client for this service package's AWS API.
func (p *servicePackage) NewClient(ctx context.Context, config map[string]any) (*fms.Client, error) {
	cfg := *(config["aws_sdkv2_config"].(*aws.Config))

	return fms.NewFromConfig(cfg, func(o *fms.Options) {
		if endpoint := config[names.AttrEndpoint].(string); endpoint != "" {
			tflog.Debug(ctx, "setting endpoint", map[string]any{
				"tf_aws.endpoint": endpoint,
			})
			o.BaseEndpoint = aws.String(endpoint)

			if o.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled {
				tflog.Debug(ctx, "endpoint set, ignoring UseFIPSEndpoint setting")
				o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
			}
		}

		o.Retryer = conns.AddIsErrorRetryables(cfg.Retryer().(aws.RetryerV2), retry.IsErrorRetryableFunc(func(err error) aws.Ternary {
			// Acceptance testing creates and deletes resources in quick succession.
			// The FMS onboarding process into Organizations is opaque to consumers.
			// Since we cannot reasonably check this status before receiving the error,
			// set the operation as retryable.
			if errs.IsAErrorMessageContains[*awstypes.InvalidOperationException](err, "Your AWS Organization is currently onboarding with AWS Firewall Manager and cannot be offboarded") ||
				errs.IsAErrorMessageContains[*awstypes.InvalidOperationException](err, "Your AWS Organization is currently offboarding with AWS Firewall Manager. Please submit onboard request after offboarded") {
				return aws.TrueTernary
			}
			return aws.UnknownTernary // Delegate to configured Retryer.
		}))
	}), nil
}
