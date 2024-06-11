// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ec2

// Exports for use in other modules.
var (
	CustomFiltersBlock                                             = customFiltersBlock
	DeleteNetworkInterface                                         = deleteNetworkInterface
	DetachNetworkInterface                                         = detachNetworkInterface
	FindImageByID                                                  = findImageByID
	FindInstanceByID                                               = findInstanceByID
	FindNetworkInterfacesByAttachmentInstanceOwnerIDAndDescription = findNetworkInterfacesByAttachmentInstanceOwnerIDAndDescription
	FindNetworkInterfacesV2                                        = findNetworkInterfaces
	FindSecurityGroupByNameAndVPCID                                = findSecurityGroupByNameAndVPCID
	FindVPCByIDV2                                                  = findVPCByID
	FindVPCEndpointByID                                            = findVPCEndpointByID
	NewCustomFilterListFrameworkV2                                 = newCustomFilterListFrameworkV2
	NewFilter                                                      = newFilter
	NewFilterV2                                                    = newFilterV2
	ResourceAMI                                                    = resourceAMI
	ResourceTransitGateway                                         = resourceTransitGateway
	ResourceTransitGatewayConnectPeer                              = resourceTransitGatewayConnectPeer
	VPCEndpointCreationTimeout                                     = vpcEndpointCreationTimeout
	WaitVPCEndpointAvailable                                       = waitVPCEndpointAvailable
)
