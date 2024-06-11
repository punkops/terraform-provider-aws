// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cognitoidp

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_cognito_user_pool", name="User Pool")
// @Tags
func resourceUserPool() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceUserPoolCreate,
		ReadWithoutTimeout:   resourceUserPoolRead,
		UpdateWithoutTimeout: resourceUserPoolUpdate,
		DeleteWithoutTimeout: resourceUserPoolDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"account_recovery_setting": {
				Type:             schema.TypeList,
				Optional:         true,
				MaxItems:         1,
				DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"recovery_mechanism": {
							Type:     schema.TypeSet,
							Optional: true,
							Computed: true,
							MinItems: 1,
							MaxItems: 2,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									names.AttrName: {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice(cognitoidentityprovider.RecoveryOptionNameType_Values(), false),
									},
									names.AttrPriority: {
										Type:     schema.TypeInt,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"admin_create_user_config": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow_admin_create_user_only": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"invite_message_template": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"email_message": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolInviteTemplateEmailMessage,
									},
									"email_subject": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolTemplateEmailSubject,
									},
									"sms_message": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validUserPoolInviteTemplateSMSMessage,
									},
								},
							},
						},
					},
				},
			},
			"alias_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(cognitoidentityprovider.AliasAttributeType_Values(), false),
				},
				ConflictsWith: []string{"username_attributes"},
			},
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"auto_verified_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(cognitoidentityprovider.VerifiedAttributeType_Values(), false),
				},
			},
			names.AttrCreationDate: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"custom_domain": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDeletionProtection: {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      cognitoidentityprovider.DeletionProtectionTypeInactive,
				ValidateFunc: validation.StringInSlice(cognitoidentityprovider.DeletionProtectionType_Values(), false),
			},
			"device_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"challenge_required_on_new_device": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"device_only_remembered_on_user_prompt": {
							Type:     schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
			names.AttrDomain: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"email_configuration": {
				Type:             schema.TypeList,
				Optional:         true,
				MaxItems:         1,
				DiffSuppressFunc: verify.SuppressMissingOptionalConfigurationBlock,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"configuration_set": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"email_sending_account": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      cognitoidentityprovider.EmailSendingAccountTypeCognitoDefault,
							ValidateFunc: validation.StringInSlice(cognitoidentityprovider.EmailSendingAccountType_Values(), false),
						},
						"from_email_address": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"reply_to_email_address": {
							Type:     schema.TypeString,
							Optional: true,
							ValidateFunc: validation.Any(
								validation.StringInSlice([]string{""}, false),
								validation.StringMatch(regexache.MustCompile(`[\p{L}\p{M}\p{S}\p{N}\p{P}]+@[\p{L}\p{M}\p{S}\p{N}\p{P}]+`),
									`must satisfy regular expression pattern: [\p{L}\p{M}\p{S}\p{N}\p{P}]+@[\p{L}\p{M}\p{S}\p{N}\p{P}]+`),
							),
						},
						"source_arn": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
					},
				},
			},
			"email_verification_message": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolEmailVerificationMessage,
				ConflictsWith: []string{"verification_message_template.0.email_message"},
			},
			"email_verification_subject": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolEmailVerificationSubject,
				ConflictsWith: []string{"verification_message_template.0.email_subject"},
			},
			"estimated_number_of_users": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			names.AttrEndpoint: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"lambda_config": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"create_auth_challenge": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"custom_email_sender": {
							Type:         schema.TypeList,
							Optional:     true,
							MaxItems:     1,
							RequiredWith: []string{"lambda_config.0.kms_key_id"},
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice(cognitoidentityprovider.CustomEmailSenderLambdaVersionType_Values(), false),
									},
								},
							},
						},
						"custom_message": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"custom_sms_sender": {
							Type:         schema.TypeList,
							Optional:     true,
							MaxItems:     1,
							RequiredWith: []string{"lambda_config.0.kms_key_id"},
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice(cognitoidentityprovider.CustomSMSSenderLambdaVersionType_Values(), false),
									},
								},
							},
						},
						"define_auth_challenge": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						names.AttrKMSKeyID: {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"post_authentication": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"post_confirmation": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_authentication": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_sign_up": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_token_generation": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: verify.ValidARN,
						},
						"pre_token_generation_config": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"lambda_arn": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: verify.ValidARN,
									},
									"lambda_version": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice(cognitoidentityprovider.PreTokenGenerationLambdaVersionType_Values(), false),
									},
								},
							},
						},
						"user_migration": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
						"verify_auth_challenge_response": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: verify.ValidARN,
						},
					},
				},
			},
			"last_modified_date": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mfa_configuration": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      cognitoidentityprovider.UserPoolMfaTypeOff,
				ValidateFunc: validation.StringInSlice(cognitoidentityprovider.UserPoolMfaType_Values(), false),
			},
			names.AttrName: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.Any(
					validation.StringLenBetween(1, 128),
					validation.StringMatch(regexache.MustCompile(`[\w\s+=,.@-]+`),
						`must satisfy regular expression pattern: [\w\s+=,.@-]+`),
				),
			},
			"password_policy": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"minimum_length": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(6, 99),
						},
						"require_lowercase": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_numbers": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_symbols": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"require_uppercase": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"temporary_password_validity_days": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(0, 365),
						},
					},
				},
			},
			names.AttrSchema: {
				Type:     schema.TypeSet,
				Optional: true,
				MinItems: 1,
				MaxItems: 50,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attribute_data_type": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice(cognitoidentityprovider.AttributeDataType_Values(), false),
						},
						"developer_only_attribute": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"mutable": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						names.AttrName: {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validUserPoolSchemaName,
						},
						"number_attribute_constraints": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"max_value": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"min_value": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"required": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"string_attribute_constraints": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"max_length": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"min_length": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"sms_authentication_message": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validUserPoolSMSAuthenticationMessage,
			},
			"sms_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrExternalID: {
							Type:     schema.TypeString,
							Required: true,
						},
						"sns_caller_arn": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: verify.ValidARN,
						},
						"sns_region": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: verify.ValidRegionName,
						},
					},
				},
			},
			"sms_verification_message": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ValidateFunc:  validUserPoolSMSVerificationMessage,
				ConflictsWith: []string{"verification_message_template.0.sms_message"},
			},
			"software_token_mfa_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MinItems: 1,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrEnabled: {
							Type:     schema.TypeBool,
							Required: true,
						},
					},
				},
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
			"user_attribute_update_settings": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attributes_require_verification_before_update": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringInSlice(cognitoidentityprovider.VerifiedAttributeType_Values(), false),
							},
						},
					},
				},
			},
			"user_pool_add_ons": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"advanced_security_mode": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice(cognitoidentityprovider.AdvancedSecurityModeType_Values(), false),
						},
					},
				},
			},
			"username_attributes": {
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(cognitoidentityprovider.UsernameAttributeType_Values(), false),
				},
				ConflictsWith: []string{"alias_attributes"},
			},
			"username_configuration": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"case_sensitive": {
							Type:     schema.TypeBool,
							Required: true,
							ForceNew: true,
						},
					},
				},
			},
			"verification_message_template": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"default_email_option": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      cognitoidentityprovider.DefaultEmailOptionTypeConfirmWithCode,
							ValidateFunc: validation.StringInSlice(cognitoidentityprovider.DefaultEmailOptionType_Values(), false),
						},
						"email_message": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateEmailMessage,
							ConflictsWith: []string{"email_verification_message"},
						},
						"email_message_by_link": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validUserPoolTemplateEmailMessageByLink,
						},
						"email_subject": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateEmailSubject,
							ConflictsWith: []string{"email_verification_subject"},
						},
						"email_subject_by_link": {
							Type:         schema.TypeString,
							Optional:     true,
							Computed:     true,
							ValidateFunc: validUserPoolTemplateEmailSubjectByLink,
						},
						"sms_message": {
							Type:          schema.TypeString,
							Optional:      true,
							Computed:      true,
							ValidateFunc:  validUserPoolTemplateSMSMessage,
							ConflictsWith: []string{"sms_verification_message"},
						},
					},
				},
			},
		},

		CustomizeDiff: verify.SetTagsDiff,
	}
}

func resourceUserPoolCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	name := d.Get(names.AttrName).(string)
	input := &cognitoidentityprovider.CreateUserPoolInput{
		PoolName:     aws.String(name),
		UserPoolTags: getTagsIn(ctx),
	}

	if v, ok := d.GetOk("account_recovery_setting"); ok {
		if config, ok := v.([]interface{})[0].(map[string]interface{}); ok {
			input.AccountRecoverySetting = expandUserPoolAccountRecoverySettingConfig(config)
		}
	}

	if v, ok := d.GetOk("admin_create_user_config"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.AdminCreateUserConfig = expandUserPoolAdminCreateUserConfig(config)
		}
	}

	if v, ok := d.GetOk("alias_attributes"); ok {
		input.AliasAttributes = flex.ExpandStringSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("auto_verified_attributes"); ok {
		input.AutoVerifiedAttributes = flex.ExpandStringSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("email_configuration"); ok && len(v.([]interface{})) > 0 {
		input.EmailConfiguration = expandUserPoolEmailConfig(v.([]interface{}))
	}

	if v, ok := d.GetOk(names.AttrDeletionProtection); ok {
		input.DeletionProtection = aws.String(v.(string))
	}

	if v, ok := d.GetOk("device_configuration"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.DeviceConfiguration = expandUserPoolDeviceConfiguration(config)
		}
	}

	if v, ok := d.GetOk("email_verification_subject"); ok {
		input.EmailVerificationSubject = aws.String(v.(string))
	}

	if v, ok := d.GetOk("email_verification_message"); ok {
		input.EmailVerificationMessage = aws.String(v.(string))
	}

	if v, ok := d.GetOk("lambda_config"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.LambdaConfig = expandUserPoolLambdaConfig(config)
		}
	}

	if v, ok := d.GetOk("password_policy"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			policies := &cognitoidentityprovider.UserPoolPolicyType{}
			policies.PasswordPolicy = expandUserPoolPasswordPolicy(config)
			input.Policies = policies
		}
	}

	if v, ok := d.GetOk(names.AttrSchema); ok {
		input.Schema = expandUserPoolSchema(v.(*schema.Set).List())
	}

	// For backwards compatibility, include this outside of MFA configuration
	// since its configuration is allowed by the API even without SMS MFA.
	if v, ok := d.GetOk("sms_authentication_message"); ok {
		input.SmsAuthenticationMessage = aws.String(v.(string))
	}

	// Include the SMS configuration outside of MFA configuration since it
	// can be used for user verification.
	if v, ok := d.GetOk("sms_configuration"); ok {
		input.SmsConfiguration = expandSMSConfiguration(v.([]interface{}))
	}

	if v, ok := d.GetOk("sms_verification_message"); ok {
		input.SmsVerificationMessage = aws.String(v.(string))
	}

	if v, ok := d.GetOk("username_attributes"); ok {
		input.UsernameAttributes = flex.ExpandStringSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("username_configuration"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.UsernameConfiguration = expandUserPoolUsernameConfiguration(config)
		}
	}

	if v, ok := d.GetOk("user_attribute_update_settings"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.UserAttributeUpdateSettings = expandUserPoolUserAttributeUpdateSettings(config)
		}
	}

	if v, ok := d.GetOk("user_pool_add_ons"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok {
			userPoolAddons := &cognitoidentityprovider.UserPoolAddOnsType{}

			if v, ok := config["advanced_security_mode"]; ok && v.(string) != "" {
				userPoolAddons.AdvancedSecurityMode = aws.String(v.(string))
			}
			input.UserPoolAddOns = userPoolAddons
		}
	}

	if v, ok := d.GetOk("verification_message_template"); ok {
		configs := v.([]interface{})
		config, ok := configs[0].(map[string]interface{})

		if ok && config != nil {
			input.VerificationMessageTemplate = expandUserPoolVerificationMessageTemplate(config)
		}
	}

	outputRaw, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
		return conn.CreateUserPoolWithContext(ctx, input)
	}, userPoolErrorRetryable)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Cognito User Pool (%s): %s", name, err)
	}

	d.SetId(aws.StringValue(outputRaw.(*cognitoidentityprovider.CreateUserPoolOutput).UserPool.Id))

	if v := d.Get("mfa_configuration").(string); v != cognitoidentityprovider.UserPoolMfaTypeOff {
		input := &cognitoidentityprovider.SetUserPoolMfaConfigInput{
			MfaConfiguration:              aws.String(v),
			SoftwareTokenMfaConfiguration: expandSoftwareTokenMFAConfiguration(d.Get("software_token_mfa_configuration").([]interface{})),
			UserPoolId:                    aws.String(d.Id()),
		}

		if v := d.Get("sms_configuration").([]interface{}); len(v) > 0 && v[0] != nil {
			input.SmsMfaConfiguration = &cognitoidentityprovider.SmsMfaConfigType{
				SmsConfiguration: expandSMSConfiguration(v),
			}

			if v, ok := d.GetOk("sms_authentication_message"); ok {
				input.SmsMfaConfiguration.SmsAuthenticationMessage = aws.String(v.(string))
			}
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
			return conn.SetUserPoolMfaConfigWithContext(ctx, input)
		}, userPoolErrorRetryable)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
		}
	}

	return append(diags, resourceUserPoolRead(ctx, d, meta)...)
}

func resourceUserPoolRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	userPool, err := findUserPoolByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Cognito User Pool %s not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool (%s): %s", d.Id(), err)
	}

	if err := d.Set("account_recovery_setting", flattenUserPoolAccountRecoverySettingConfig(userPool.AccountRecoverySetting)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting account_recovery_setting: %s", err)
	}
	if err := d.Set("admin_create_user_config", flattenUserPoolAdminCreateUserConfig(userPool.AdminCreateUserConfig)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting admin_create_user_config: %s", err)
	}
	if userPool.AliasAttributes != nil {
		d.Set("alias_attributes", aws.StringValueSlice(userPool.AliasAttributes))
	}
	d.Set(names.AttrARN, userPool.Arn)
	d.Set("auto_verified_attributes", aws.StringValueSlice(userPool.AutoVerifiedAttributes))
	d.Set(names.AttrCreationDate, userPool.CreationDate.Format(time.RFC3339))
	d.Set("custom_domain", userPool.CustomDomain)
	d.Set(names.AttrDeletionProtection, userPool.DeletionProtection)
	if err := d.Set("device_configuration", flattenUserPoolDeviceConfiguration(userPool.DeviceConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting device_configuration: %s", err)
	}
	d.Set(names.AttrDomain, userPool.Domain)
	if err := d.Set("email_configuration", flattenUserPoolEmailConfiguration(userPool.EmailConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting email_configuration: %s", err)
	}
	d.Set("email_verification_subject", userPool.EmailVerificationSubject)
	d.Set("email_verification_message", userPool.EmailVerificationMessage)
	d.Set(names.AttrEndpoint, fmt.Sprintf("%s/%s", meta.(*conns.AWSClient).RegionalHostname(ctx, "cognito-idp"), d.Id()))
	d.Set("estimated_number_of_users", userPool.EstimatedNumberOfUsers)
	if err := d.Set("lambda_config", flattenUserPoolLambdaConfig(userPool.LambdaConfig)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting lambda_config: %s", err)
	}
	d.Set("last_modified_date", userPool.LastModifiedDate.Format(time.RFC3339))
	d.Set(names.AttrName, userPool.Name)
	if err := d.Set("password_policy", flattenUserPoolPasswordPolicy(userPool.Policies.PasswordPolicy)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting password_policy: %s", err)
	}
	var configuredSchema []interface{}
	if v, ok := d.GetOk(names.AttrSchema); ok {
		configuredSchema = v.(*schema.Set).List()
	}
	if err := d.Set(names.AttrSchema, flattenUserPoolSchema(expandUserPoolSchema(configuredSchema), userPool.SchemaAttributes)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting schema: %s", err)
	}
	d.Set("sms_authentication_message", userPool.SmsAuthenticationMessage)
	if err := d.Set("sms_configuration", flattenSMSConfiguration(userPool.SmsConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting sms_configuration: %s", err)
	}
	d.Set("sms_verification_message", userPool.SmsVerificationMessage)
	if err := d.Set("user_attribute_update_settings", flattenUserPoolUserAttributeUpdateSettings(userPool.UserAttributeUpdateSettings)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting user_attribute_update_settings: %s", err)
	}
	if err := d.Set("user_pool_add_ons", flattenUserPoolUserPoolAddOns(userPool.UserPoolAddOns)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting user_pool_add_ons: %s", err)
	}
	d.Set("username_attributes", flex.FlattenStringSet(userPool.UsernameAttributes))
	if err := d.Set("username_configuration", flattenUserPoolUsernameConfiguration(userPool.UsernameConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting username_configuration: %s", err)
	}
	if err := d.Set("verification_message_template", flattenUserPoolVerificationMessageTemplate(userPool.VerificationMessageTemplate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting verification_message_template: %s", err)
	}

	setTagsOut(ctx, userPool.UserPoolTags)

	input := &cognitoidentityprovider.GetUserPoolMfaConfigInput{
		UserPoolId: aws.String(d.Id()),
	}

	output, err := conn.GetUserPoolMfaConfigWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
	}

	d.Set("mfa_configuration", output.MfaConfiguration)
	if err := d.Set("software_token_mfa_configuration", flattenSoftwareTokenMFAConfiguration(output.SoftwareTokenMfaConfiguration)); err != nil {
		return sdkdiag.AppendErrorf(diags, "setting software_token_mfa_configuration: %s", err)
	}

	return diags
}

func resourceUserPoolUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	// MFA updates.
	if d.HasChanges(
		"mfa_configuration",
		"sms_authentication_message",
		"sms_configuration",
		"software_token_mfa_configuration",
	) {
		mfaConfiguration := d.Get("mfa_configuration").(string)
		input := &cognitoidentityprovider.SetUserPoolMfaConfigInput{
			MfaConfiguration:              aws.String(mfaConfiguration),
			SoftwareTokenMfaConfiguration: expandSoftwareTokenMFAConfiguration(d.Get("software_token_mfa_configuration").([]interface{})),
			UserPoolId:                    aws.String(d.Id()),
		}

		// Since SMS configuration applies to both verification and MFA, only include if MFA is enabled.
		// Otherwise, the API will return the following error:
		// InvalidParameterException: Invalid MFA configuration given, can't turn off MFA and configure an MFA together.
		if v := d.Get("sms_configuration").([]interface{}); len(v) > 0 && v[0] != nil && mfaConfiguration != cognitoidentityprovider.UserPoolMfaTypeOff {
			input.SmsMfaConfiguration = &cognitoidentityprovider.SmsMfaConfigType{
				SmsConfiguration: expandSMSConfiguration(v),
			}

			if v, ok := d.GetOk("sms_authentication_message"); ok {
				input.SmsMfaConfiguration.SmsAuthenticationMessage = aws.String(v.(string))
			}
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout, func() (any, error) {
			return conn.SetUserPoolMfaConfigWithContext(ctx, input)
		}, userPoolErrorRetryable)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting Cognito User Pool (%s) MFA configuration: %s", d.Id(), err)
		}
	}

	// Non MFA updates
	// NOTES:
	//  * Include SMS configuration changes since settings are shared between verification and MFA.
	//  * For backwards compatibility, include SMS authentication message changes without SMS MFA since the API allows it.
	if d.HasChanges(
		"account_recovery_setting",
		"admin_create_user_config",
		"auto_verified_attributes",
		names.AttrDeletionProtection,
		"device_configuration",
		"email_configuration",
		"email_verification_message",
		"email_verification_subject",
		"lambda_config",
		"password_policy",
		"sms_authentication_message",
		"sms_configuration",
		"sms_verification_message",
		names.AttrTags,
		names.AttrTagsAll,
		"user_attribute_update_settings",
		"user_pool_add_ons",
		"verification_message_template",
	) {
		input := &cognitoidentityprovider.UpdateUserPoolInput{
			UserPoolId:   aws.String(d.Id()),
			UserPoolTags: getTagsIn(ctx),
		}

		if v, ok := d.GetOk("account_recovery_setting"); ok {
			if config, ok := v.([]interface{})[0].(map[string]interface{}); ok {
				input.AccountRecoverySetting = expandUserPoolAccountRecoverySettingConfig(config)
			}
		}

		if v, ok := d.GetOk("admin_create_user_config"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if ok && config != nil {
				input.AdminCreateUserConfig = expandUserPoolAdminCreateUserConfig(config)
			}
		}

		if v, ok := d.GetOk("auto_verified_attributes"); ok {
			input.AutoVerifiedAttributes = flex.ExpandStringSet(v.(*schema.Set))
		}

		if v, ok := d.GetOk(names.AttrDeletionProtection); ok {
			input.DeletionProtection = aws.String(v.(string))
		}

		if v, ok := d.GetOk("device_configuration"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if ok && config != nil {
				input.DeviceConfiguration = expandUserPoolDeviceConfiguration(config)
			}
		}

		if v, ok := d.GetOk("email_configuration"); ok && len(v.([]interface{})) > 0 {
			input.EmailConfiguration = expandUserPoolEmailConfig(v.([]interface{}))
		}

		if v, ok := d.GetOk("email_verification_subject"); ok {
			input.EmailVerificationSubject = aws.String(v.(string))
		}

		if v, ok := d.GetOk("email_verification_message"); ok {
			input.EmailVerificationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("lambda_config"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})
			if ok && config != nil {
				if d.HasChange("lambda_config.0.pre_token_generation") {
					config["pre_token_generation_config"].([]interface{})[0].(map[string]interface{})["lambda_arn"] = d.Get("lambda_config.0.pre_token_generation")
				}

				if d.HasChange("lambda_config.0.pre_token_generation_config.0.lambda_arn") {
					config["pre_token_generation"] = d.Get("lambda_config.0.pre_token_generation_config.0.lambda_arn")
				}

				input.LambdaConfig = expandUserPoolLambdaConfig(config)
			}
		}

		if v, ok := d.GetOk("mfa_configuration"); ok {
			input.MfaConfiguration = aws.String(v.(string))
		}

		if v, ok := d.GetOk("password_policy"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if ok && config != nil {
				policies := &cognitoidentityprovider.UserPoolPolicyType{}
				policies.PasswordPolicy = expandUserPoolPasswordPolicy(config)
				input.Policies = policies
			}
		}

		if v, ok := d.GetOk("sms_authentication_message"); ok {
			input.SmsAuthenticationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("sms_configuration"); ok {
			input.SmsConfiguration = expandSMSConfiguration(v.([]interface{}))
		}

		if v, ok := d.GetOk("sms_verification_message"); ok {
			input.SmsVerificationMessage = aws.String(v.(string))
		}

		if v, ok := d.GetOk("user_attribute_update_settings"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if ok && config != nil {
				input.UserAttributeUpdateSettings = expandUserPoolUserAttributeUpdateSettings(config)
			}
		}
		if d.HasChange("user_attribute_update_settings") && input.UserAttributeUpdateSettings == nil {
			// An empty array must be sent to disable this setting if previously enabled. A nil
			// UserAttibutesUpdateSetting param will result in no modifications.
			input.UserAttributeUpdateSettings = &cognitoidentityprovider.UserAttributeUpdateSettingsType{
				AttributesRequireVerificationBeforeUpdate: []*string{},
			}
		}

		if v, ok := d.GetOk("user_pool_add_ons"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if ok && config != nil {
				userPoolAddons := &cognitoidentityprovider.UserPoolAddOnsType{}

				if v, ok := config["advanced_security_mode"]; ok && v.(string) != "" {
					userPoolAddons.AdvancedSecurityMode = aws.String(v.(string))
				}
				input.UserPoolAddOns = userPoolAddons
			}
		}

		if v, ok := d.GetOk("verification_message_template"); ok {
			configs := v.([]interface{})
			config, ok := configs[0].(map[string]interface{})

			if d.HasChange("email_verification_message") {
				config["email_message"] = d.Get("email_verification_message")
			}
			if d.HasChange("email_verification_subject") {
				config["email_subject"] = d.Get("email_verification_subject")
			}
			if d.HasChange("sms_verification_message") {
				config["sms_message"] = d.Get("sms_verification_message")
			}

			if ok && config != nil {
				input.VerificationMessageTemplate = expandUserPoolVerificationMessageTemplate(config)
			}
		}

		_, err := tfresource.RetryWhen(ctx, propagationTimeout,
			func() (any, error) {
				return conn.UpdateUserPoolWithContext(ctx, input)
			},
			func(err error) (bool, error) {
				if ok, err := userPoolErrorRetryable(err); ok {
					return true, err
				}

				switch {
				case tfawserr.ErrMessageContains(err, cognitoidentityprovider.ErrCodeInvalidParameterException, "Please use TemporaryPasswordValidityDays in PasswordPolicy instead of UnusedAccountValidityDays") && input.AdminCreateUserConfig.UnusedAccountValidityDays != nil:
					input.AdminCreateUserConfig.UnusedAccountValidityDays = nil
					return true, err

				default:
					return false, err
				}
			})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Cognito User Pool (%s): %s", d.Id(), err)
		}
	}

	if d.HasChange(names.AttrSchema) {
		o, n := d.GetChange(names.AttrSchema)
		os, ns := o.(*schema.Set), n.(*schema.Set)

		if os.Difference(ns).Len() == 0 {
			input := &cognitoidentityprovider.AddCustomAttributesInput{
				CustomAttributes: expandUserPoolSchema(ns.Difference(os).List()),
				UserPoolId:       aws.String(d.Id()),
			}

			_, err := conn.AddCustomAttributesWithContext(ctx, input)

			if err != nil {
				return sdkdiag.AppendErrorf(diags, "adding Cognito User Pool (%s) custom attributes: %s", d.Id(), err)
			}
		} else {
			return sdkdiag.AppendErrorf(diags, "updating Cognito User Pool (%s): cannot modify or remove schema items", d.Id())
		}
	}

	return append(diags, resourceUserPoolRead(ctx, d, meta)...)
}

func resourceUserPoolDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CognitoIDPConn(ctx)

	log.Printf("[DEBUG] Deleting Cognito User Pool: %s", d.Id())
	_, err := conn.DeleteUserPoolWithContext(ctx, &cognitoidentityprovider.DeleteUserPoolInput{
		UserPoolId: aws.String(d.Id()),
	})

	if tfawserr.ErrCodeEquals(err, cognitoidentityprovider.ErrCodeResourceNotFoundException) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Cognito user pool (%s): %s", d.Id(), err)
	}

	return diags
}

// IAM roles & policies can take some time to propagate and be attached to the User Pool.
func userPoolErrorRetryable(err error) (bool, error) {
	switch {
	case tfawserr.ErrMessageContains(err, cognitoidentityprovider.ErrCodeInvalidSmsRoleTrustRelationshipException, "Role does not have a trust relationship allowing Cognito to assume the role"),
		tfawserr.ErrMessageContains(err, cognitoidentityprovider.ErrCodeInvalidSmsRoleAccessPolicyException, "Role does not have permission to publish with SNS"):
		return true, err

	default:
		return false, err
	}
}

func findUserPoolByID(ctx context.Context, conn *cognitoidentityprovider.CognitoIdentityProvider, id string) (*cognitoidentityprovider.UserPoolType, error) {
	input := &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(id),
	}

	output, err := conn.DescribeUserPoolWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, cognitoidentityprovider.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.UserPool == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.UserPool, nil
}

func expandSMSConfiguration(tfList []interface{}) *cognitoidentityprovider.SmsConfigurationType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]interface{})

	apiObject := &cognitoidentityprovider.SmsConfigurationType{}

	if v, ok := tfMap[names.AttrExternalID].(string); ok && v != "" {
		apiObject.ExternalId = aws.String(v)
	}

	if v, ok := tfMap["sns_caller_arn"].(string); ok && v != "" {
		apiObject.SnsCallerArn = aws.String(v)
	}

	if v, ok := tfMap["sns_region"].(string); ok && v != "" {
		apiObject.SnsRegion = aws.String(v)
	}

	return apiObject
}

func expandSoftwareTokenMFAConfiguration(tfList []interface{}) *cognitoidentityprovider.SoftwareTokenMfaConfigType {
	if len(tfList) == 0 || tfList[0] == nil {
		return nil
	}

	tfMap := tfList[0].(map[string]interface{})

	apiObject := &cognitoidentityprovider.SoftwareTokenMfaConfigType{}

	if v, ok := tfMap[names.AttrEnabled].(bool); ok {
		apiObject.Enabled = aws.Bool(v)
	}

	return apiObject
}

func flattenSMSConfiguration(apiObject *cognitoidentityprovider.SmsConfigurationType) []interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.ExternalId; v != nil {
		tfMap[names.AttrExternalID] = aws.StringValue(v)
	}

	if v := apiObject.SnsCallerArn; v != nil {
		tfMap["sns_caller_arn"] = aws.StringValue(v)
	}

	if v := apiObject.SnsRegion; v != nil {
		tfMap["sns_region"] = aws.StringValue(v)
	}

	return []interface{}{tfMap}
}

func flattenSoftwareTokenMFAConfiguration(apiObject *cognitoidentityprovider.SoftwareTokenMfaConfigType) []interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if v := apiObject.Enabled; v != nil {
		tfMap[names.AttrEnabled] = aws.BoolValue(v)
	}

	return []interface{}{tfMap}
}

func expandUserPoolAccountRecoverySettingConfig(config map[string]interface{}) *cognitoidentityprovider.AccountRecoverySettingType {
	if len(config) == 0 {
		return nil
	}

	configs := &cognitoidentityprovider.AccountRecoverySettingType{}

	mechs := make([]*cognitoidentityprovider.RecoveryOptionType, 0)

	if v, ok := config["recovery_mechanism"]; ok {
		data := v.(*schema.Set).List()

		for _, m := range data {
			param := m.(map[string]interface{})
			opt := &cognitoidentityprovider.RecoveryOptionType{}

			if v, ok := param[names.AttrName]; ok {
				opt.Name = aws.String(v.(string))
			}

			if v, ok := param[names.AttrPriority]; ok {
				opt.Priority = aws.Int64(int64(v.(int)))
			}

			mechs = append(mechs, opt)
		}
	}

	configs.RecoveryMechanisms = mechs

	return configs
}

func flattenUserPoolAccountRecoverySettingConfig(config *cognitoidentityprovider.AccountRecoverySettingType) []interface{} {
	if config == nil || len(config.RecoveryMechanisms) == 0 {
		return nil
	}

	settings := map[string]interface{}{}

	mechanisms := make([]map[string]interface{}, 0)

	for _, conf := range config.RecoveryMechanisms {
		mech := map[string]interface{}{
			names.AttrName:     aws.StringValue(conf.Name),
			names.AttrPriority: aws.Int64Value(conf.Priority),
		}
		mechanisms = append(mechanisms, mech)
	}

	settings["recovery_mechanism"] = mechanisms

	return []interface{}{settings}
}

func flattenUserPoolEmailConfiguration(s *cognitoidentityprovider.EmailConfigurationType) []map[string]interface{} {
	m := make(map[string]interface{})

	if s == nil {
		return nil
	}

	if s.ReplyToEmailAddress != nil {
		m["reply_to_email_address"] = aws.StringValue(s.ReplyToEmailAddress)
	}

	if s.From != nil {
		m["from_email_address"] = aws.StringValue(s.From)
	}

	if s.SourceArn != nil {
		m["source_arn"] = aws.StringValue(s.SourceArn)
	}

	if s.EmailSendingAccount != nil {
		m["email_sending_account"] = aws.StringValue(s.EmailSendingAccount)
	}

	if s.ConfigurationSet != nil {
		m["configuration_set"] = aws.StringValue(s.ConfigurationSet)
	}

	if len(m) > 0 {
		return []map[string]interface{}{m}
	}

	return []map[string]interface{}{}
}

func expandUserPoolAdminCreateUserConfig(config map[string]interface{}) *cognitoidentityprovider.AdminCreateUserConfigType {
	configs := &cognitoidentityprovider.AdminCreateUserConfigType{}

	if v, ok := config["allow_admin_create_user_only"]; ok {
		configs.AllowAdminCreateUserOnly = aws.Bool(v.(bool))
	}

	if v, ok := config["invite_message_template"]; ok {
		data := v.([]interface{})

		if len(data) > 0 {
			m, ok := data[0].(map[string]interface{})

			if ok {
				imt := &cognitoidentityprovider.MessageTemplateType{}

				if v, ok := m["email_message"]; ok {
					imt.EmailMessage = aws.String(v.(string))
				}

				if v, ok := m["email_subject"]; ok {
					imt.EmailSubject = aws.String(v.(string))
				}

				if v, ok := m["sms_message"]; ok {
					imt.SMSMessage = aws.String(v.(string))
				}

				configs.InviteMessageTemplate = imt
			}
		}
	}

	return configs
}

func flattenUserPoolAdminCreateUserConfig(s *cognitoidentityprovider.AdminCreateUserConfigType) []map[string]interface{} {
	config := map[string]interface{}{}

	if s == nil {
		return nil
	}

	if s.AllowAdminCreateUserOnly != nil {
		config["allow_admin_create_user_only"] = aws.BoolValue(s.AllowAdminCreateUserOnly)
	}

	if s.InviteMessageTemplate != nil {
		subconfig := map[string]interface{}{}

		if s.InviteMessageTemplate.EmailMessage != nil {
			subconfig["email_message"] = aws.StringValue(s.InviteMessageTemplate.EmailMessage)
		}

		if s.InviteMessageTemplate.EmailSubject != nil {
			subconfig["email_subject"] = aws.StringValue(s.InviteMessageTemplate.EmailSubject)
		}

		if s.InviteMessageTemplate.SMSMessage != nil {
			subconfig["sms_message"] = aws.StringValue(s.InviteMessageTemplate.SMSMessage)
		}

		if len(subconfig) > 0 {
			config["invite_message_template"] = []map[string]interface{}{subconfig}
		}
	}

	return []map[string]interface{}{config}
}

func expandUserPoolDeviceConfiguration(config map[string]interface{}) *cognitoidentityprovider.DeviceConfigurationType {
	configs := &cognitoidentityprovider.DeviceConfigurationType{}

	if v, ok := config["challenge_required_on_new_device"]; ok {
		configs.ChallengeRequiredOnNewDevice = aws.Bool(v.(bool))
	}

	if v, ok := config["device_only_remembered_on_user_prompt"]; ok {
		configs.DeviceOnlyRememberedOnUserPrompt = aws.Bool(v.(bool))
	}

	return configs
}

func expandUserPoolLambdaConfig(config map[string]interface{}) *cognitoidentityprovider.LambdaConfigType {
	configs := &cognitoidentityprovider.LambdaConfigType{}

	if v, ok := config["create_auth_challenge"]; ok && v.(string) != "" {
		configs.CreateAuthChallenge = aws.String(v.(string))
	}

	if v, ok := config["custom_message"]; ok && v.(string) != "" {
		configs.CustomMessage = aws.String(v.(string))
	}

	if v, ok := config["define_auth_challenge"]; ok && v.(string) != "" {
		configs.DefineAuthChallenge = aws.String(v.(string))
	}

	if v, ok := config["post_authentication"]; ok && v.(string) != "" {
		configs.PostAuthentication = aws.String(v.(string))
	}

	if v, ok := config["post_confirmation"]; ok && v.(string) != "" {
		configs.PostConfirmation = aws.String(v.(string))
	}

	if v, ok := config["pre_authentication"]; ok && v.(string) != "" {
		configs.PreAuthentication = aws.String(v.(string))
	}

	if v, ok := config["pre_sign_up"]; ok && v.(string) != "" {
		configs.PreSignUp = aws.String(v.(string))
	}

	if v, ok := config["pre_token_generation"]; ok && v.(string) != "" {
		configs.PreTokenGeneration = aws.String(v.(string))
	}

	if v, ok := config["pre_token_generation_config"].([]interface{}); ok && len(v) > 0 {
		s, sok := v[0].(map[string]interface{})
		if sok && s != nil {
			configs.PreTokenGenerationConfig = expandedUserPoolPreGenerationConfig(s)
		}
	}

	if v, ok := config["user_migration"]; ok && v.(string) != "" {
		configs.UserMigration = aws.String(v.(string))
	}

	if v, ok := config["verify_auth_challenge_response"]; ok && v.(string) != "" {
		configs.VerifyAuthChallengeResponse = aws.String(v.(string))
	}

	if v, ok := config[names.AttrKMSKeyID]; ok && v.(string) != "" {
		configs.KMSKeyID = aws.String(v.(string))
	}

	if v, ok := config["custom_sms_sender"].([]interface{}); ok && len(v) > 0 {
		s, sok := v[0].(map[string]interface{})
		if sok && s != nil {
			configs.CustomSMSSender = expandUserPoolCustomSMSSender(s)
		}
	}

	if v, ok := config["custom_email_sender"].([]interface{}); ok && len(v) > 0 {
		s, sok := v[0].(map[string]interface{})
		if sok && s != nil {
			configs.CustomEmailSender = expandUserPoolCustomEmailSender(s)
		}
	}

	return configs
}

func flattenUserPoolLambdaConfig(s *cognitoidentityprovider.LambdaConfigType) []map[string]interface{} {
	m := map[string]interface{}{}
	if s == nil {
		return nil
	}

	if s.CreateAuthChallenge != nil {
		m["create_auth_challenge"] = aws.StringValue(s.CreateAuthChallenge)
	}

	if s.CustomMessage != nil {
		m["custom_message"] = aws.StringValue(s.CustomMessage)
	}

	if s.DefineAuthChallenge != nil {
		m["define_auth_challenge"] = aws.StringValue(s.DefineAuthChallenge)
	}

	if s.PostAuthentication != nil {
		m["post_authentication"] = aws.StringValue(s.PostAuthentication)
	}

	if s.PostConfirmation != nil {
		m["post_confirmation"] = aws.StringValue(s.PostConfirmation)
	}

	if s.PreAuthentication != nil {
		m["pre_authentication"] = aws.StringValue(s.PreAuthentication)
	}

	if s.PreSignUp != nil {
		m["pre_sign_up"] = aws.StringValue(s.PreSignUp)
	}

	if s.PreTokenGeneration != nil {
		m["pre_token_generation"] = aws.StringValue(s.PreTokenGeneration)
	}

	if s.PreTokenGenerationConfig != nil {
		m["pre_token_generation_config"] = flattenUserPoolPreTokenGenerationConfig(s.PreTokenGenerationConfig)
	}

	if s.UserMigration != nil {
		m["user_migration"] = aws.StringValue(s.UserMigration)
	}

	if s.VerifyAuthChallengeResponse != nil {
		m["verify_auth_challenge_response"] = aws.StringValue(s.VerifyAuthChallengeResponse)
	}

	if s.KMSKeyID != nil {
		m[names.AttrKMSKeyID] = aws.StringValue(s.KMSKeyID)
	}

	if s.CustomSMSSender != nil {
		m["custom_sms_sender"] = flattenUserPoolCustomSMSSender(s.CustomSMSSender)
	}

	if s.CustomEmailSender != nil {
		m["custom_email_sender"] = flattenUserPoolCustomEmailSender(s.CustomEmailSender)
	}

	if len(m) > 0 {
		return []map[string]interface{}{m}
	}

	return []map[string]interface{}{}
}

func expandUserPoolPasswordPolicy(config map[string]interface{}) *cognitoidentityprovider.PasswordPolicyType {
	configs := &cognitoidentityprovider.PasswordPolicyType{}

	if v, ok := config["minimum_length"]; ok {
		configs.MinimumLength = aws.Int64(int64(v.(int)))
	}

	if v, ok := config["require_lowercase"]; ok {
		configs.RequireLowercase = aws.Bool(v.(bool))
	}

	if v, ok := config["require_numbers"]; ok {
		configs.RequireNumbers = aws.Bool(v.(bool))
	}

	if v, ok := config["require_symbols"]; ok {
		configs.RequireSymbols = aws.Bool(v.(bool))
	}

	if v, ok := config["require_uppercase"]; ok {
		configs.RequireUppercase = aws.Bool(v.(bool))
	}

	if v, ok := config["temporary_password_validity_days"]; ok {
		configs.TemporaryPasswordValidityDays = aws.Int64(int64(v.(int)))
	}

	return configs
}

func flattenUserPoolUserPoolAddOns(s *cognitoidentityprovider.UserPoolAddOnsType) []map[string]interface{} {
	config := make(map[string]interface{})

	if s == nil {
		return []map[string]interface{}{}
	}

	if s.AdvancedSecurityMode != nil {
		config["advanced_security_mode"] = aws.StringValue(s.AdvancedSecurityMode)
	}

	return []map[string]interface{}{config}
}

func expandUserPoolSchema(inputs []interface{}) []*cognitoidentityprovider.SchemaAttributeType {
	configs := make([]*cognitoidentityprovider.SchemaAttributeType, len(inputs))

	for i, input := range inputs {
		param := input.(map[string]interface{})
		config := &cognitoidentityprovider.SchemaAttributeType{}

		if v, ok := param["attribute_data_type"]; ok {
			config.AttributeDataType = aws.String(v.(string))
		}

		if v, ok := param["developer_only_attribute"]; ok {
			config.DeveloperOnlyAttribute = aws.Bool(v.(bool))
		}

		if v, ok := param["mutable"]; ok {
			config.Mutable = aws.Bool(v.(bool))
		}

		if v, ok := param[names.AttrName]; ok {
			config.Name = aws.String(v.(string))
		}

		if v, ok := param["required"]; ok {
			config.Required = aws.Bool(v.(bool))
		}

		if v, ok := param["number_attribute_constraints"]; ok {
			data := v.([]interface{})

			if len(data) > 0 {
				m, ok := data[0].(map[string]interface{})
				if ok {
					numberAttributeConstraintsType := &cognitoidentityprovider.NumberAttributeConstraintsType{}

					if v, ok := m["min_value"]; ok && v.(string) != "" {
						numberAttributeConstraintsType.MinValue = aws.String(v.(string))
					}

					if v, ok := m["max_value"]; ok && v.(string) != "" {
						numberAttributeConstraintsType.MaxValue = aws.String(v.(string))
					}

					config.NumberAttributeConstraints = numberAttributeConstraintsType
				}
			}
		}

		if v, ok := param["string_attribute_constraints"]; ok {
			data := v.([]interface{})

			if len(data) > 0 {
				m, _ := data[0].(map[string]interface{})
				if ok {
					stringAttributeConstraintsType := &cognitoidentityprovider.StringAttributeConstraintsType{}

					if l, ok := m["min_length"]; ok && l.(string) != "" {
						stringAttributeConstraintsType.MinLength = aws.String(l.(string))
					}

					if l, ok := m["max_length"]; ok && l.(string) != "" {
						stringAttributeConstraintsType.MaxLength = aws.String(l.(string))
					}

					config.StringAttributeConstraints = stringAttributeConstraintsType
				}
			}
		}

		configs[i] = config
	}

	return configs
}

func flattenUserPoolSchema(configuredAttributes, inputs []*cognitoidentityprovider.SchemaAttributeType) []map[string]interface{} {
	values := make([]map[string]interface{}, 0)

	for _, input := range inputs {
		if input == nil {
			continue
		}

		// The API returns all standard attributes
		// https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
		// Ignore setting them in state if they are unconfigured to prevent a huge and unexpected diff
		configured := false

		for _, configuredAttribute := range configuredAttributes {
			if reflect.DeepEqual(input, configuredAttribute) {
				configured = true
			}
		}

		if !configured {
			if UserPoolSchemaAttributeMatchesStandardAttribute(input) {
				continue
			}
			// When adding a Cognito Identity Provider, the API will automatically add an "identities" attribute
			identitiesAttribute := cognitoidentityprovider.SchemaAttributeType{
				AttributeDataType:          aws.String(cognitoidentityprovider.AttributeDataTypeString),
				DeveloperOnlyAttribute:     aws.Bool(false),
				Mutable:                    aws.Bool(true),
				Name:                       aws.String("identities"),
				Required:                   aws.Bool(false),
				StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{},
			}
			if reflect.DeepEqual(*input, identitiesAttribute) {
				continue
			}
		}

		var value = map[string]interface{}{
			"attribute_data_type":      aws.StringValue(input.AttributeDataType),
			"developer_only_attribute": aws.BoolValue(input.DeveloperOnlyAttribute),
			"mutable":                  aws.BoolValue(input.Mutable),
			names.AttrName:             strings.TrimPrefix(strings.TrimPrefix(aws.StringValue(input.Name), "dev:"), "custom:"),
			"required":                 aws.BoolValue(input.Required),
		}

		if input.NumberAttributeConstraints != nil {
			subvalue := make(map[string]interface{})

			if input.NumberAttributeConstraints.MinValue != nil {
				subvalue["min_value"] = aws.StringValue(input.NumberAttributeConstraints.MinValue)
			}

			if input.NumberAttributeConstraints.MaxValue != nil {
				subvalue["max_value"] = aws.StringValue(input.NumberAttributeConstraints.MaxValue)
			}

			value["number_attribute_constraints"] = []map[string]interface{}{subvalue}
		}

		if input.StringAttributeConstraints != nil && !skipFlatteningStringAttributeContraints(configuredAttributes, input) {
			subvalue := make(map[string]interface{})

			if input.StringAttributeConstraints.MinLength != nil {
				subvalue["min_length"] = aws.StringValue(input.StringAttributeConstraints.MinLength)
			}

			if input.StringAttributeConstraints.MaxLength != nil {
				subvalue["max_length"] = aws.StringValue(input.StringAttributeConstraints.MaxLength)
			}

			value["string_attribute_constraints"] = []map[string]interface{}{subvalue}
		}

		values = append(values, value)
	}

	return values
}

func expandUserPoolUsernameConfiguration(config map[string]interface{}) *cognitoidentityprovider.UsernameConfigurationType {
	usernameConfigurationType := &cognitoidentityprovider.UsernameConfigurationType{
		CaseSensitive: aws.Bool(config["case_sensitive"].(bool)),
	}

	return usernameConfigurationType
}

func flattenUserPoolUsernameConfiguration(u *cognitoidentityprovider.UsernameConfigurationType) []map[string]interface{} {
	m := map[string]interface{}{}

	if u == nil {
		return nil
	}

	m["case_sensitive"] = aws.BoolValue(u.CaseSensitive)

	return []map[string]interface{}{m}
}

func expandUserPoolVerificationMessageTemplate(config map[string]interface{}) *cognitoidentityprovider.VerificationMessageTemplateType {
	verificationMessageTemplateType := &cognitoidentityprovider.VerificationMessageTemplateType{}

	if v, ok := config["default_email_option"]; ok && v.(string) != "" {
		verificationMessageTemplateType.DefaultEmailOption = aws.String(v.(string))
	}

	if v, ok := config["email_message"]; ok && v.(string) != "" {
		verificationMessageTemplateType.EmailMessage = aws.String(v.(string))
	}

	if v, ok := config["email_message_by_link"]; ok && v.(string) != "" {
		verificationMessageTemplateType.EmailMessageByLink = aws.String(v.(string))
	}

	if v, ok := config["email_subject"]; ok && v.(string) != "" {
		verificationMessageTemplateType.EmailSubject = aws.String(v.(string))
	}

	if v, ok := config["email_subject_by_link"]; ok && v.(string) != "" {
		verificationMessageTemplateType.EmailSubjectByLink = aws.String(v.(string))
	}

	if v, ok := config["sms_message"]; ok && v.(string) != "" {
		verificationMessageTemplateType.SmsMessage = aws.String(v.(string))
	}

	return verificationMessageTemplateType
}

func flattenUserPoolVerificationMessageTemplate(s *cognitoidentityprovider.VerificationMessageTemplateType) []map[string]interface{} {
	m := map[string]interface{}{}

	if s == nil {
		return nil
	}

	if s.DefaultEmailOption != nil {
		m["default_email_option"] = aws.StringValue(s.DefaultEmailOption)
	}

	if s.EmailMessage != nil {
		m["email_message"] = aws.StringValue(s.EmailMessage)
	}

	if s.EmailMessageByLink != nil {
		m["email_message_by_link"] = aws.StringValue(s.EmailMessageByLink)
	}

	if s.EmailSubject != nil {
		m["email_subject"] = aws.StringValue(s.EmailSubject)
	}

	if s.EmailSubjectByLink != nil {
		m["email_subject_by_link"] = aws.StringValue(s.EmailSubjectByLink)
	}

	if s.SmsMessage != nil {
		m["sms_message"] = aws.StringValue(s.SmsMessage)
	}

	if len(m) > 0 {
		return []map[string]interface{}{m}
	}

	return []map[string]interface{}{}
}

func flattenUserPoolDeviceConfiguration(s *cognitoidentityprovider.DeviceConfigurationType) []map[string]interface{} {
	config := map[string]interface{}{}

	if s == nil {
		return nil
	}

	if s.ChallengeRequiredOnNewDevice != nil {
		config["challenge_required_on_new_device"] = aws.BoolValue(s.ChallengeRequiredOnNewDevice)
	}

	if s.DeviceOnlyRememberedOnUserPrompt != nil {
		config["device_only_remembered_on_user_prompt"] = aws.BoolValue(s.DeviceOnlyRememberedOnUserPrompt)
	}

	return []map[string]interface{}{config}
}

func flattenUserPoolPasswordPolicy(s *cognitoidentityprovider.PasswordPolicyType) []map[string]interface{} {
	m := map[string]interface{}{}

	if s == nil {
		return nil
	}

	if s.MinimumLength != nil {
		m["minimum_length"] = aws.Int64Value(s.MinimumLength)
	}

	if s.RequireLowercase != nil {
		m["require_lowercase"] = aws.BoolValue(s.RequireLowercase)
	}

	if s.RequireNumbers != nil {
		m["require_numbers"] = aws.BoolValue(s.RequireNumbers)
	}

	if s.RequireSymbols != nil {
		m["require_symbols"] = aws.BoolValue(s.RequireSymbols)
	}

	if s.RequireUppercase != nil {
		m["require_uppercase"] = aws.BoolValue(s.RequireUppercase)
	}

	if s.TemporaryPasswordValidityDays != nil {
		m["temporary_password_validity_days"] = aws.Int64Value(s.TemporaryPasswordValidityDays)
	}

	if len(m) > 0 {
		return []map[string]interface{}{m}
	}

	return []map[string]interface{}{}
}

func UserPoolSchemaAttributeMatchesStandardAttribute(input *cognitoidentityprovider.SchemaAttributeType) bool {
	if input == nil {
		return false
	}

	// All standard attributes always returned by API
	// https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
	var standardAttributes = []cognitoidentityprovider.SchemaAttributeType{
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrAddress),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("birthdate"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("10"),
				MinLength: aws.String("10"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrEmail),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeBoolean),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("email_verified"),
			Required:               aws.Bool(false),
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("gender"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("given_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("family_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("locale"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("middle_name"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrName),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("nickname"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("phone_number"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeBoolean),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("phone_number_verified"),
			Required:               aws.Bool(false),
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("picture"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("preferred_username"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String(names.AttrProfile),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(false),
			Name:                   aws.String("sub"),
			Required:               aws.Bool(true),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("1"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeNumber),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("updated_at"),
			NumberAttributeConstraints: &cognitoidentityprovider.NumberAttributeConstraintsType{
				MinValue: aws.String("0"),
			},
			Required: aws.Bool(false),
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("website"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
		{
			AttributeDataType:      aws.String(cognitoidentityprovider.AttributeDataTypeString),
			DeveloperOnlyAttribute: aws.Bool(false),
			Mutable:                aws.Bool(true),
			Name:                   aws.String("zoneinfo"),
			Required:               aws.Bool(false),
			StringAttributeConstraints: &cognitoidentityprovider.StringAttributeConstraintsType{
				MaxLength: aws.String("2048"),
				MinLength: aws.String("0"),
			},
		},
	}
	for _, standardAttribute := range standardAttributes {
		if reflect.DeepEqual(*input, standardAttribute) {
			return true
		}
	}
	return false
}

func expandedUserPoolPreGenerationConfig(config map[string]interface{}) *cognitoidentityprovider.PreTokenGenerationVersionConfigType {
	preTokenGenerationConfig := &cognitoidentityprovider.PreTokenGenerationVersionConfigType{
		LambdaArn:     aws.String(config["lambda_arn"].(string)),
		LambdaVersion: aws.String(config["lambda_version"].(string)),
	}

	return preTokenGenerationConfig
}

func flattenUserPoolPreTokenGenerationConfig(u *cognitoidentityprovider.PreTokenGenerationVersionConfigType) []map[string]interface{} {
	m := map[string]interface{}{}

	if u == nil {
		return nil
	}

	m["lambda_arn"] = aws.StringValue(u.LambdaArn)
	m["lambda_version"] = aws.StringValue(u.LambdaVersion)

	return []map[string]interface{}{m}
}

func expandUserPoolCustomSMSSender(config map[string]interface{}) *cognitoidentityprovider.CustomSMSLambdaVersionConfigType {
	usernameConfigurationType := &cognitoidentityprovider.CustomSMSLambdaVersionConfigType{
		LambdaArn:     aws.String(config["lambda_arn"].(string)),
		LambdaVersion: aws.String(config["lambda_version"].(string)),
	}

	return usernameConfigurationType
}

func flattenUserPoolCustomSMSSender(u *cognitoidentityprovider.CustomSMSLambdaVersionConfigType) []map[string]interface{} {
	m := map[string]interface{}{}

	if u == nil {
		return nil
	}

	m["lambda_arn"] = aws.StringValue(u.LambdaArn)
	m["lambda_version"] = aws.StringValue(u.LambdaVersion)

	return []map[string]interface{}{m}
}

func expandUserPoolCustomEmailSender(config map[string]interface{}) *cognitoidentityprovider.CustomEmailLambdaVersionConfigType {
	usernameConfigurationType := &cognitoidentityprovider.CustomEmailLambdaVersionConfigType{
		LambdaArn:     aws.String(config["lambda_arn"].(string)),
		LambdaVersion: aws.String(config["lambda_version"].(string)),
	}

	return usernameConfigurationType
}

func flattenUserPoolCustomEmailSender(u *cognitoidentityprovider.CustomEmailLambdaVersionConfigType) []map[string]interface{} {
	m := map[string]interface{}{}

	if u == nil {
		return nil
	}

	m["lambda_arn"] = aws.StringValue(u.LambdaArn)
	m["lambda_version"] = aws.StringValue(u.LambdaVersion)

	return []map[string]interface{}{m}
}

func expandUserPoolEmailConfig(emailConfig []interface{}) *cognitoidentityprovider.EmailConfigurationType {
	config := emailConfig[0].(map[string]interface{})

	emailConfigurationType := &cognitoidentityprovider.EmailConfigurationType{}

	if v, ok := config["reply_to_email_address"]; ok && v.(string) != "" {
		emailConfigurationType.ReplyToEmailAddress = aws.String(v.(string))
	}

	if v, ok := config["source_arn"]; ok && v.(string) != "" {
		emailConfigurationType.SourceArn = aws.String(v.(string))
	}

	if v, ok := config["from_email_address"]; ok && v.(string) != "" {
		emailConfigurationType.From = aws.String(v.(string))
	}

	if v, ok := config["email_sending_account"]; ok && v.(string) != "" {
		emailConfigurationType.EmailSendingAccount = aws.String(v.(string))
	}

	if v, ok := config["configuration_set"]; ok && v.(string) != "" {
		emailConfigurationType.ConfigurationSet = aws.String(v.(string))
	}

	return emailConfigurationType
}

func expandUserPoolUserAttributeUpdateSettings(config map[string]interface{}) *cognitoidentityprovider.UserAttributeUpdateSettingsType {
	userAttributeUpdateSettings := &cognitoidentityprovider.UserAttributeUpdateSettingsType{}
	if v, ok := config["attributes_require_verification_before_update"]; ok {
		userAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate = flex.ExpandStringSet(v.(*schema.Set))
	}

	return userAttributeUpdateSettings
}

func flattenUserPoolUserAttributeUpdateSettings(u *cognitoidentityprovider.UserAttributeUpdateSettingsType) []map[string]interface{} {
	if u == nil {
		return nil
	}
	// If this setting is enabled then disabled, the API returns a nested empty slice instead of nil
	if len(u.AttributesRequireVerificationBeforeUpdate) == 0 {
		return nil
	}

	m := map[string]interface{}{}
	m["attributes_require_verification_before_update"] = flex.FlattenStringSet(u.AttributesRequireVerificationBeforeUpdate)

	return []map[string]interface{}{m}
}

// skipFlatteningStringAttributeContraints returns true when all of the schema arguments
// match an existing configured attribute, except an empty "string_attribute_constraints" block.
// In this situation the Describe API returns default constraint values, and a persistent diff
// would be present if written to state.
func skipFlatteningStringAttributeContraints(configuredAttributes []*cognitoidentityprovider.SchemaAttributeType, input *cognitoidentityprovider.SchemaAttributeType) bool {
	skip := false
	for _, configuredAttribute := range configuredAttributes {
		// Root elements are all equal
		if reflect.DeepEqual(input.AttributeDataType, configuredAttribute.AttributeDataType) &&
			reflect.DeepEqual(input.DeveloperOnlyAttribute, configuredAttribute.DeveloperOnlyAttribute) &&
			reflect.DeepEqual(input.Mutable, configuredAttribute.Mutable) &&
			reflect.DeepEqual(input.Name, configuredAttribute.Name) &&
			reflect.DeepEqual(input.Required, configuredAttribute.Required) &&
			// The configured "string_attribute_constraints" object is empty, but the returned value is not
			(aws.StringValue(configuredAttribute.AttributeDataType) == cognitoidentityprovider.AttributeDataTypeString &&
				configuredAttribute.StringAttributeConstraints == nil &&
				input.StringAttributeConstraints != nil) {
			skip = true
		}
	}
	return skip
}
