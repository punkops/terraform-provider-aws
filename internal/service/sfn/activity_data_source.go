// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sfn

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKDataSource("aws_sfn_activity")
func DataSourceActivity() *schema.Resource {
	return &schema.Resource{
		ReadWithoutTimeout: dataSourceActivityRead,

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ExactlyOneOf: []string{
					names.AttrARN,
					names.AttrName,
				},
			},
			names.AttrCreationDate: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrName: {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ExactlyOneOf: []string{
					names.AttrARN,
					names.AttrName,
				},
			},
		},
	}
}

func dataSourceActivityRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SFNConn(ctx)

	if v, ok := d.GetOk(names.AttrName); ok {
		name := v.(string)
		var activities []*sfn.ActivityListItem

		err := conn.ListActivitiesPagesWithContext(ctx, &sfn.ListActivitiesInput{}, func(page *sfn.ListActivitiesOutput, lastPage bool) bool {
			if page == nil {
				return !lastPage
			}

			for _, v := range page.Activities {
				if name == aws.StringValue(v.Name) {
					activities = append(activities, v)
				}
			}

			return !lastPage
		})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "listing Step Functions Activities: %s", err)
		}

		if n := len(activities); n == 0 {
			return sdkdiag.AppendErrorf(diags, "no Step Functions Activities matched")
		} else if n > 1 {
			return sdkdiag.AppendErrorf(diags, "%d Step Functions Activities matched; use additional constraints to reduce matches to a single Activity", n)
		}

		activity := activities[0]

		arn := aws.StringValue(activity.ActivityArn)
		d.SetId(arn)
		d.Set(names.AttrARN, arn)
		d.Set(names.AttrCreationDate, activity.CreationDate.Format(time.RFC3339))
		d.Set(names.AttrName, activity.Name)
	} else if v, ok := d.GetOk(names.AttrARN); ok {
		arn := v.(string)
		activity, err := FindActivityByARN(ctx, conn, arn)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "reading Step Functions Activity (%s): %s", arn, err)
		}

		arn = aws.StringValue(activity.ActivityArn)
		d.SetId(arn)
		d.Set(names.AttrARN, arn)
		d.Set(names.AttrCreationDate, activity.CreationDate.Format(time.RFC3339))
		d.Set(names.AttrName, activity.Name)
	}

	return diags
}
