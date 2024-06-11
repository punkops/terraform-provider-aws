// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrock_test

import (
	"testing"

	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

func TestAccBedrock_serial(t *testing.T) {
	t.Parallel()

	testCases := map[string]map[string]func(t *testing.T){
		"ModelInvocationLoggingConfiguration": {
			acctest.CtBasic:      testAccModelInvocationLoggingConfiguration_basic,
			acctest.CtDisappears: testAccModelInvocationLoggingConfiguration_disappears,
		},
	}

	acctest.RunSerialTests2Levels(t, testCases, 0)
}
