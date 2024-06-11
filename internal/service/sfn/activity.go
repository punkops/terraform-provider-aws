// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sfn

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_sfn_activity", name="Activity")
// @Tags(identifierAttribute="id")
func ResourceActivity() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceActivityCreate,
		ReadWithoutTimeout:   resourceActivityRead,
		UpdateWithoutTimeout: resourceActivityUpdate,
		DeleteWithoutTimeout: resourceActivityDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			names.AttrCreationDate: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrName: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(0, 80),
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},

		CustomizeDiff: verify.SetTagsDiff,
	}
}

func resourceActivityCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SFNConn(ctx)

	name := d.Get(names.AttrName).(string)
	input := &sfn.CreateActivityInput{
		Name: aws.String(name),
		Tags: getTagsIn(ctx),
	}

	output, err := conn.CreateActivityWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Step Functions Activity (%s): %s", name, err)
	}

	d.SetId(aws.StringValue(output.ActivityArn))

	return append(diags, resourceActivityRead(ctx, d, meta)...)
}

func resourceActivityRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SFNConn(ctx)

	output, err := FindActivityByARN(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Step Functions Activity (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Step Functions Activity (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrCreationDate, output.CreationDate.Format(time.RFC3339))
	d.Set(names.AttrName, output.Name)

	return diags
}

func resourceActivityUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Tags only.
	return resourceActivityRead(ctx, d, meta)
}

func resourceActivityDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SFNConn(ctx)

	log.Printf("[DEBUG] Deleting Step Functions Activity: %s", d.Id())
	_, err := conn.DeleteActivityWithContext(ctx, &sfn.DeleteActivityInput{
		ActivityArn: aws.String(d.Id()),
	})

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Step Functions Activity (%s): %s", d.Id(), err)
	}

	return diags
}

func FindActivityByARN(ctx context.Context, conn *sfn.SFN, arn string) (*sfn.DescribeActivityOutput, error) {
	input := &sfn.DescribeActivityInput{
		ActivityArn: aws.String(arn),
	}

	output, err := conn.DescribeActivityWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, sfn.ErrCodeActivityDoesNotExist) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.CreationDate == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}
