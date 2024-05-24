// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package opensearch

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/opensearchservice"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_opensearch_vpc_endpoint_access")
func ResourceVPCEndpointAccess() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceVPCEndpointAccessCreate,
		ReadWithoutTimeout:   resourceVPCEndpointAccessRead,
		DeleteWithoutTimeout: resourceVPCEndpointAccessDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(60 * time.Minute),
			Delete: schema.DefaultTimeout(90 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			names.AttrDomainName: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"account": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: verify.ValidAccountID,
			},
		},
	}
}

func resourceVPCEndpointAccessCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).OpenSearchConn(ctx)

	output, err := conn.AuthorizeVpcEndpointAccessWithContext(ctx, &opensearchservice.AuthorizeVpcEndpointAccessInput{
		DomainName: aws.String(d.Get(names.AttrDomainName).(string)),
		Account:    aws.String(d.Get("account").(string)),
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating OpenSearch VPC endpoint access: %s", err)
	}

	d.SetId(aws.StringValue(output.AuthorizedPrincipal.Principal))
	log.Printf("[INFO] OpenSearch VPC Endpoint Access ID: %s", d.Id())

	return append(diags, resourceVPCEndpointAccessRead(ctx, d, meta)...)
}

func resourceVPCEndpointAccessRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).OpenSearchConn(ctx)

	_, err := findVPCEndpointAccessPrincipalByID(ctx, conn, d.Get(names.AttrDomainName).(string), d.Id())

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading OpenSearch VPC endpoint access: %s", err)
	}

	return diags
}

func findVPCEndpointAccessPrincipalByID(ctx context.Context, conn *opensearchservice.OpenSearchService, domain string, id string) (string, error) {
	output, err := conn.ListVpcEndpointAccessWithContext(ctx, &opensearchservice.ListVpcEndpointAccessInput{
		DomainName: aws.String(domain),
	})

	if err != nil {
		return "", err
	}

	for _, access := range output.AuthorizedPrincipalList {
		if aws.StringValue(access.Principal) == id {
			return aws.StringValue(access.Principal), nil
		}
	}

	return "", fmt.Errorf("VPC Endpoint Principal not found for domain: %s and ID: %s", domain, id)
}

func resourceVPCEndpointAccessDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).OpenSearchConn(ctx)

	log.Printf("[DEBUG] Deleting OpenSearch VPC Endpoint Access: %s", d.Id())
	_, err := conn.RevokeVpcEndpointAccessWithContext(ctx, &opensearchservice.RevokeVpcEndpointAccessInput{
		DomainName: aws.String(d.Get(names.AttrDomainName).(string)),
		Account:    aws.String(d.Get("account").(string)),
	})

	if tfawserr.ErrCodeEquals(err, opensearchservice.ErrCodeResourceNotFoundException) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting OpenSearch VPC Endpoint Access (%s): %s", d.Id(), err)
	}

	return diags
}
