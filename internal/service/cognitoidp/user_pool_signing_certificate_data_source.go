// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cognitoidp

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKDataSource("aws_cognito_user_pool_signing_certificate", name="User Pool Signing Certificate")
func dataSourceUserPoolSigningCertificate() *schema.Resource {
	return &schema.Resource{
		ReadWithoutTimeout: dataSourceUserPoolSigningCertificateRead,

		Schema: map[string]*schema.Schema{
			names.AttrCertificate: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrUserPoolID: {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceUserPoolSigningCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	userPoolID := d.Get(names.AttrUserPoolID).(string)
	input := &cognitoidentityprovider.GetSigningCertificateInput{
		UserPoolId: aws.String(userPoolID),
	}

	output, err := conn.GetSigningCertificateWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool (%s) Signing Certificate: %s", userPoolID, err)
	}

	d.SetId(userPoolID)
	d.Set(names.AttrCertificate, output.Certificate)

	return diags
}
