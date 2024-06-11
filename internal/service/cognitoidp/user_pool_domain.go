// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cognitoidp

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_cognito_user_pool_domain", name="User Pool Domain")
func resourceUserPoolDomain() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceUserPoolDomainCreate,
		ReadWithoutTimeout:   resourceUserPoolDomainRead,
		UpdateWithoutTimeout: resourceUserPoolDomainUpdate,
		DeleteWithoutTimeout: resourceUserPoolDomainDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			names.AttrAWSAccountID: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrCertificateARN: {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: verify.ValidARN,
			},
			"cloudfront_distribution": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cloudfront_distribution_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cloudfront_distribution_zone_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDomain: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, 63),
			},
			names.AttrS3Bucket: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrUserPoolID: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			names.AttrVersion: {
				Type:     schema.TypeString,
				Computed: true,
			},
		},

		CustomizeDiff: customdiff.ForceNewIfChange(names.AttrCertificateARN, func(_ context.Context, old, new, meta interface{}) bool {
			// If the cert arn is being changed to a new arn, don't force new.
			return !(old.(string) != "" && new.(string) != "")
		}),
	}
}

func resourceUserPoolDomainCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	domain := d.Get(names.AttrDomain).(string)
	timeout := 1 * time.Minute
	input := &cognitoidentityprovider.CreateUserPoolDomainInput{
		Domain:     aws.String(domain),
		UserPoolId: aws.String(d.Get(names.AttrUserPoolID).(string)),
	}

	if v, ok := d.GetOk(names.AttrCertificateARN); ok {
		input.CustomDomainConfig = &cognitoidentityprovider.CustomDomainConfigType{
			CertificateArn: aws.String(v.(string)),
		}
		timeout = 60 * time.Minute // Custom domains take more time to become active.
	}

	_, err := conn.CreateUserPoolDomainWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Cognito User Pool Domain (%s): %s", domain, err)
	}

	d.SetId(domain)

	if _, err := waitUserPoolDomainCreated(ctx, conn, d.Id(), timeout); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Cognito User Pool Domain (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceUserPoolDomainRead(ctx, d, meta)...)
}

func resourceUserPoolDomainRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	desc, err := FindUserPoolDomain(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		create.LogNotFoundRemoveState(names.CognitoIDP, create.ErrActionReading, ResNameUserPoolDomain, d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool Domain (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrAWSAccountID, desc.AWSAccountId)
	d.Set(names.AttrCertificateARN, "")
	if desc.CustomDomainConfig != nil {
		d.Set(names.AttrCertificateARN, desc.CustomDomainConfig.CertificateArn)
	}
	d.Set("cloudfront_distribution", desc.CloudFrontDistribution)
	d.Set("cloudfront_distribution_arn", desc.CloudFrontDistribution)
	d.Set("cloudfront_distribution_zone_id", meta.(*conns.AWSClient).CloudFrontDistributionHostedZoneID(ctx))
	d.Set(names.AttrDomain, d.Id())
	d.Set(names.AttrS3Bucket, desc.S3Bucket)
	d.Set(names.AttrUserPoolID, desc.UserPoolId)
	d.Set(names.AttrVersion, desc.Version)

	return diags
}

func resourceUserPoolDomainUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	input := &cognitoidentityprovider.UpdateUserPoolDomainInput{
		CustomDomainConfig: &cognitoidentityprovider.CustomDomainConfigType{
			CertificateArn: aws.String(d.Get(names.AttrCertificateARN).(string)),
		},
		Domain:     aws.String(d.Id()),
		UserPoolId: aws.String(d.Get(names.AttrUserPoolID).(string)),
	}

	_, err := conn.UpdateUserPoolDomainWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "updating Cognito User Pool Domain (%s): %s", d.Id(), err)
	}

	const (
		timeout = 60 * time.Minute // Update is only for cert arns on custom domains, which take more time to become active.
	)
	if _, err := waitUserPoolDomainUpdated(ctx, conn, d.Id(), timeout); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Cognito User Pool Domain (%s) update: %s", d.Id(), err)
	}

	return append(diags, resourceUserPoolDomainRead(ctx, d, meta)...)
}

func resourceUserPoolDomainDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	log.Printf("[DEBUG] Deleting Cognito User Pool Domain: %s", d.Id())
	_, err := conn.DeleteUserPoolDomainWithContext(ctx, &cognitoidentityprovider.DeleteUserPoolDomainInput{
		Domain:     aws.String(d.Id()),
		UserPoolId: aws.String(d.Get(names.AttrUserPoolID).(string)),
	})

	if tfawserr.ErrMessageContains(err, cognitoidentityprovider.ErrCodeInvalidParameterException, "No such domain") {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Cognito User Pool Domain (%s): %s", d.Id(), err)
	}

	if _, err := waitUserPoolDomainDeleted(ctx, conn, d.Id(), 1*time.Minute); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Cognito User Pool Domain (%s) delete: %s", d.Id(), err)
	}

	return diags
}

func FindUserPoolDomain(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, domain string) (*cognitoidentityprovider.DomainDescriptionType, error) {
	input := &cognitoidentityprovider.DescribeUserPoolDomainInput{
		Domain: aws.String(domain),
	}

	output, err := conn.DescribeUserPoolDomainWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, cognitoidentityprovider.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	// e.g.
	// {
	// 	"DomainDescription": {}
	// }
	if output == nil || output.DomainDescription == nil || output.DomainDescription.Status == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.DomainDescription, nil
}

func statusUserPoolDomain(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, domain string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := FindUserPoolDomain(ctx, conn, domain)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.StringValue(output.Status), nil
	}
}

func waitUserPoolDomainCreated(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, domain string, timeout time.Duration) (*cognitoidentityprovider.DomainDescriptionType, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{cognitoidentityprovider.DomainStatusTypeCreating, cognitoidentityprovider.DomainStatusTypeUpdating},
		Target:  []string{cognitoidentityprovider.DomainStatusTypeActive},
		Refresh: statusUserPoolDomain(ctx, conn, domain),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*cognitoidentityprovider.DomainDescriptionType); ok {
		return output, err
	}

	return nil, err
}

func waitUserPoolDomainUpdated(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, domain string, timeout time.Duration) (*cognitoidentityprovider.DomainDescriptionType, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{cognitoidentityprovider.DomainStatusTypeUpdating},
		Target:  []string{cognitoidentityprovider.DomainStatusTypeActive},
		Refresh: statusUserPoolDomain(ctx, conn, domain),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*cognitoidentityprovider.DomainDescriptionType); ok {
		return output, err
	}

	return nil, err
}

func waitUserPoolDomainDeleted(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, domain string, timeout time.Duration) (*cognitoidentityprovider.DomainDescriptionType, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{cognitoidentityprovider.DomainStatusTypeUpdating, cognitoidentityprovider.DomainStatusTypeDeleting},
		Target:  []string{},
		Refresh: statusUserPoolDomain(ctx, conn, domain),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*cognitoidentityprovider.DomainDescriptionType); ok {
		return output, err
	}

	return nil, err
}
