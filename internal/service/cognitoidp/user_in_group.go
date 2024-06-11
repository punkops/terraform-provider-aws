// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cognitoidp

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_cognito_user_in_group", name="Group User")
func resourceUserInGroup() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceUserInGroupCreate,
		ReadWithoutTimeout:   resourceUserInGroupRead,
		DeleteWithoutTimeout: resourceUserInGroupDelete,
		Schema: map[string]*schema.Schema{
			names.AttrGroupName: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validUserGroupName,
			},
			names.AttrUserPoolID: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validUserPoolID,
			},
			names.AttrUsername: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, 128),
			},
		},
	}
}

func resourceUserInGroupCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	input := &cognitoidentityprovider.AdminAddUserToGroupInput{}

	if v, ok := d.GetOk(names.AttrGroupName); ok {
		input.GroupName = aws.String(v.(string))
	}

	if v, ok := d.GetOk(names.AttrUserPoolID); ok {
		input.UserPoolId = aws.String(v.(string))
	}

	if v, ok := d.GetOk(names.AttrUsername); ok {
		input.Username = aws.String(v.(string))
	}

	_, err := conn.AdminAddUserToGroupWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "adding user to group: %s", err)
	}

	//lintignore:R015 // Allow legacy unstable ID usage in managed resource
	d.SetId(id.UniqueId())

	return append(diags, resourceUserInGroupRead(ctx, d, meta)...)
}

func resourceUserInGroupRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	groupName := d.Get(names.AttrGroupName).(string)
	userPoolId := d.Get(names.AttrUserPoolID).(string)
	username := d.Get(names.AttrUsername).(string)

	found, err := FindCognitoUserInGroup(ctx, conn, groupName, userPoolId, username)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Group Membership: %s", err)
	}

	if !found {
		d.SetId("")
	}

	return diags
}

func resourceUserInGroupDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	groupName := d.Get(names.AttrGroupName).(string)
	userPoolID := d.Get(names.AttrUserPoolID).(string)
	username := d.Get(names.AttrUsername).(string)

	input := &cognitoidentityprovider.AdminRemoveUserFromGroupInput{
		GroupName:  aws.String(groupName),
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(username),
	}

	_, err := conn.AdminRemoveUserFromGroupWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "removing user from group: %s", err)
	}

	return diags
}
