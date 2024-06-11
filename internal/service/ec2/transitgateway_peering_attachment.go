// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ec2

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hashicorp/aws-sdk-go-base/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_ec2_transit_gateway_peering_attachment", name="Transit Gateway Peering Attachment")
// @Tags(identifierAttribute="id")
// @Testing(tagsTest=false)
func resourceTransitGatewayPeeringAttachment() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceTransitGatewayPeeringAttachmentCreate,
		ReadWithoutTimeout:   resourceTransitGatewayPeeringAttachmentRead,
		UpdateWithoutTimeout: resourceTransitGatewayPeeringAttachmentUpdate,
		DeleteWithoutTimeout: resourceTransitGatewayPeeringAttachmentDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		CustomizeDiff: verify.SetTagsDiff,

		Schema: map[string]*schema.Schema{
			"peer_account_id": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Computed:     true,
				ValidateFunc: verify.ValidAccountID,
			},
			"peer_region": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"peer_transit_gateway_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			names.AttrState: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			names.AttrTransitGatewayID: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
		},
	}
}

func resourceTransitGatewayPeeringAttachmentCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EC2Client(ctx)

	peerAccountID := meta.(*conns.AWSClient).AccountID
	if v, ok := d.GetOk("peer_account_id"); ok {
		peerAccountID = v.(string)
	}
	input := &ec2.CreateTransitGatewayPeeringAttachmentInput{
		PeerAccountId:        aws.String(peerAccountID),
		PeerRegion:           aws.String(d.Get("peer_region").(string)),
		PeerTransitGatewayId: aws.String(d.Get("peer_transit_gateway_id").(string)),
		TagSpecifications:    getTagSpecificationsInV2(ctx, awstypes.ResourceTypeTransitGatewayAttachment),
		TransitGatewayId:     aws.String(d.Get(names.AttrTransitGatewayID).(string)),
	}

	log.Printf("[DEBUG] Creating EC2 Transit Gateway Peering Attachment: %+v", input)
	output, err := conn.CreateTransitGatewayPeeringAttachment(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating EC2 Transit Gateway Peering Attachment: %s", err)
	}

	d.SetId(aws.ToString(output.TransitGatewayPeeringAttachment.TransitGatewayAttachmentId))

	if _, err := waitTransitGatewayPeeringAttachmentCreated(ctx, conn, d.Id()); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for EC2 Transit Gateway Peering Attachment (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceTransitGatewayPeeringAttachmentRead(ctx, d, meta)...)
}

func resourceTransitGatewayPeeringAttachmentRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EC2Client(ctx)

	transitGatewayPeeringAttachment, err := findTransitGatewayPeeringAttachmentByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] EC2 Transit Gateway Peering Attachment (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading EC2 Transit Gateway Peering Attachment (%s): %s", d.Id(), err)
	}

	d.Set("peer_account_id", transitGatewayPeeringAttachment.AccepterTgwInfo.OwnerId)
	d.Set("peer_region", transitGatewayPeeringAttachment.AccepterTgwInfo.Region)
	d.Set("peer_transit_gateway_id", transitGatewayPeeringAttachment.AccepterTgwInfo.TransitGatewayId)
	d.Set(names.AttrState, transitGatewayPeeringAttachment.State)
	d.Set(names.AttrTransitGatewayID, transitGatewayPeeringAttachment.RequesterTgwInfo.TransitGatewayId)

	setTagsOutV2(ctx, transitGatewayPeeringAttachment.Tags)

	return diags
}

func resourceTransitGatewayPeeringAttachmentUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// Tags only.

	return append(diags, resourceTransitGatewayPeeringAttachmentRead(ctx, d, meta)...)
}

func resourceTransitGatewayPeeringAttachmentDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EC2Client(ctx)

	log.Printf("[DEBUG] Deleting EC2 Transit Gateway Peering Attachment: %s", d.Id())
	_, err := conn.DeleteTransitGatewayPeeringAttachment(ctx, &ec2.DeleteTransitGatewayPeeringAttachmentInput{
		TransitGatewayAttachmentId: aws.String(d.Id()),
	})

	if tfawserr.ErrCodeEquals(err, errCodeInvalidTransitGatewayAttachmentIDNotFound) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting EC2 Transit Gateway Peering Attachment (%s): %s", d.Id(), err)
	}

	if err := waitTransitGatewayPeeringAttachmentDeleted(ctx, conn, d.Id()); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for EC2 Transit Gateway Peering Attachment (%s) delete: %s", d.Id(), err)
	}

	return diags
}
