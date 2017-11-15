// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package organizations

const (

	// ErrCodeAWSOrganizationsNotInUseException for service response error code
	// "AWSOrganizationsNotInUseException".
	//
	// Your account is not a member of an organization. To make this request, you
	// must use the credentials of an account that belongs to an organization.
	ErrCodeAWSOrganizationsNotInUseException = "AWSOrganizationsNotInUseException"

	// ErrCodeAccessDeniedException for service response error code
	// "AccessDeniedException".
	//
	// You don't have permissions to perform the requested operation. The user or
	// role that is making the request must have at least one IAM permissions policy
	// attached that grants the required permissions. For more information, see
	// Access Management (http://docs.aws.amazon.com/IAM/latest/UserGuide/access.html)
	// in the IAM User Guide.
	ErrCodeAccessDeniedException = "AccessDeniedException"

	// ErrCodeAccessDeniedForDependencyException for service response error code
	// "AccessDeniedForDependencyException".
	//
	// The operation you attempted requires you to have the iam:CreateServiceLinkedRole
	// so that Organizations can create the required service-linked role. You do
	// not have that permission.
	ErrCodeAccessDeniedForDependencyException = "AccessDeniedForDependencyException"

	// ErrCodeAccountNotFoundException for service response error code
	// "AccountNotFoundException".
	//
	// We can't find an AWS account with the AccountId that you specified, or the
	// account whose credentials you used to make this request is not a member of
	// an organization.
	ErrCodeAccountNotFoundException = "AccountNotFoundException"

	// ErrCodeAlreadyInOrganizationException for service response error code
	// "AlreadyInOrganizationException".
	//
	// This account is already a member of an organization. An account can belong
	// to only one organization at a time.
	ErrCodeAlreadyInOrganizationException = "AlreadyInOrganizationException"

	// ErrCodeChildNotFoundException for service response error code
	// "ChildNotFoundException".
	//
	// We can't find an organizational unit (OU) or AWS account with the ChildId
	// that you specified.
	ErrCodeChildNotFoundException = "ChildNotFoundException"

	// ErrCodeConcurrentModificationException for service response error code
	// "ConcurrentModificationException".
	//
	// The target of the operation is currently being modified by a different request.
	// Try again later.
	ErrCodeConcurrentModificationException = "ConcurrentModificationException"

	// ErrCodeConstraintViolationException for service response error code
	// "ConstraintViolationException".
	//
	// Performing this operation violates a minimum or maximum value limit. For
	// example, attempting to removing the last SCP from an OU or root, inviting
	// or creating too many accounts to the organization, or attaching too many
	// policies to an account, OU, or root. This exception includes a reason that
	// contains additional information about the violated limit.
	//
	// Some of the reasons in the following list might not be applicable to this
	// specific API or operation:
	//
	// ACCOUNT_NUMBER_LIMIT_EXCEEDED: You attempted to exceed the limit on the number
	// of accounts in an organization. If you need more accounts, contact AWS Support
	// to request an increase in your limit.
	//
	// Or, The number of invitations that you tried to send would cause you to exceed
	// the limit of accounts in your organization. Send fewer invitations, or contact
	// AWS Support to request an increase in the number of accounts.
	//
	// Note: deleted and closed accounts still count toward your limit.
	//
	// If you get an exception that indicates that you exceeded your account limits
	// for the organization or that you can"t add an account because your organization
	// is still initializing, please contact  AWS Customer Support (https://console.aws.amazon.com/support/home#/).
	//
	//    * HANDSHAKE_RATE_LIMIT_EXCEEDED: You attempted to exceed the number of
	//    handshakes you can send in one day.
	//
	//    * OU_NUMBER_LIMIT_EXCEEDED: You attempted to exceed the number of organizational
	//    units you can have in an organization.
	//
	//    * OU_DEPTH_LIMIT_EXCEEDED: You attempted to create an organizational unit
	//    tree that is too many levels deep.
	//
	//    * POLICY_NUMBER_LIMIT_EXCEEDED. You attempted to exceed the number of
	//    policies that you can have in an organization.
	//
	//    * MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED: You attempted to exceed the
	//    number of policies of a certain type that can be attached to an entity
	//    at one time.
	//
	//    * MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED: You attempted to detach a
	//    policy from an entity that would cause the entity to have fewer than the
	//    minimum number of policies of a certain type required.
	//
	//    * ACCOUNT_CANNOT_LEAVE_WITHOUT_EULA: You attempted to remove an account
	//    from the organization that does not yet have enough information to exist
	//    as a stand-alone account. This account requires you to first agree to
	//    the AWS Customer Agreement. Follow the steps at To leave an organization
	//    when all required account information has not yet been provided (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html#leave-without-all-info)
	//    in the AWS Organizations User Guide.
	//
	//    * ACCOUNT_CANNOT_LEAVE_WITHOUT_PHONE_VERIFICATION: You attempted to remove
	//    an account from the organization that does not yet have enough information
	//    to exist as a stand-alone account. This account requires you to first
	//    complete phone verification. Follow the steps at To leave an organization
	//    when all required account information has not yet been provided (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html#leave-without-all-info)
	//    in the AWS Organizations User Guide.
	//
	//    * MASTER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED: To create an organization
	//    with this account, you first must associate a payment instrument, such
	//    as a credit card, with the account. Follow the steps at To leave an organization
	//    when all required account information has not yet been provided (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html#leave-without-all-info)
	//    in the AWS Organizations User Guide.
	//
	//    * MEMBER_ACCOUNT_PAYMENT_INSTRUMENT_REQUIRED: To complete this operation
	//    with this member account, you first must associate a payment instrument,
	//    such as a credit card, with the account. Follow the steps at To leave
	//    an organization when all required account information has not yet been
	//    provided (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html#leave-without-all-info)
	//    in the AWS Organizations User Guide.
	//
	//    * ACCOUNT_CREATION_RATE_LIMIT_EXCEEDED: You attempted to exceed the number
	//    of accounts that you can create in one day.
	//
	//    * MASTER_ACCOUNT_ADDRESS_DOES_NOT_MATCH_MARKETPLACE: To create an account
	//    in this organization, you first must migrate the organization's master
	//    account to the marketplace that corresponds to the master account's address.
	//    For example, accounts with India addresses must be associated with the
	//    AISPL marketplace. All accounts in an organization must be associated
	//    with the same marketplace.
	//
	//    * MASTER_ACCOUNT_MISSING_CONTACT_INFO: To complete this operation, you
	//    must first provide contact a valid address and phone number for the master
	//    account. Then try the operation again.
	ErrCodeConstraintViolationException = "ConstraintViolationException"

	// ErrCodeCreateAccountStatusNotFoundException for service response error code
	// "CreateAccountStatusNotFoundException".
	//
	// We can't find an create account request with the CreateAccountRequestId that
	// you specified.
	ErrCodeCreateAccountStatusNotFoundException = "CreateAccountStatusNotFoundException"

	// ErrCodeDestinationParentNotFoundException for service response error code
	// "DestinationParentNotFoundException".
	//
	// We can't find the destination container (a root or OU) with the ParentId
	// that you specified.
	ErrCodeDestinationParentNotFoundException = "DestinationParentNotFoundException"

	// ErrCodeDuplicateAccountException for service response error code
	// "DuplicateAccountException".
	//
	// That account is already present in the specified destination.
	ErrCodeDuplicateAccountException = "DuplicateAccountException"

	// ErrCodeDuplicateHandshakeException for service response error code
	// "DuplicateHandshakeException".
	//
	// A handshake with the same action and target already exists. For example,
	// if you invited an account to join your organization, the invited account
	// might already have a pending invitation from this organization. If you intend
	// to resend an invitation to an account, ensure that existing handshakes that
	// might be considered duplicates are canceled or declined.
	ErrCodeDuplicateHandshakeException = "DuplicateHandshakeException"

	// ErrCodeDuplicateOrganizationalUnitException for service response error code
	// "DuplicateOrganizationalUnitException".
	//
	// An organizational unit (OU) with the same name already exists.
	ErrCodeDuplicateOrganizationalUnitException = "DuplicateOrganizationalUnitException"

	// ErrCodeDuplicatePolicyAttachmentException for service response error code
	// "DuplicatePolicyAttachmentException".
	//
	// The selected policy is already attached to the specified target.
	ErrCodeDuplicatePolicyAttachmentException = "DuplicatePolicyAttachmentException"

	// ErrCodeDuplicatePolicyException for service response error code
	// "DuplicatePolicyException".
	//
	// A policy with the same name already exists.
	ErrCodeDuplicatePolicyException = "DuplicatePolicyException"

	// ErrCodeFinalizingOrganizationException for service response error code
	// "FinalizingOrganizationException".
	//
	// AWS Organizations could not finalize the creation of your organization. Try
	// again later. If this persists, contact AWS customer support.
	ErrCodeFinalizingOrganizationException = "FinalizingOrganizationException"

	// ErrCodeHandshakeAlreadyInStateException for service response error code
	// "HandshakeAlreadyInStateException".
	//
	// The specified handshake is already in the requested state. For example, you
	// can't accept a handshake that was already accepted.
	ErrCodeHandshakeAlreadyInStateException = "HandshakeAlreadyInStateException"

	// ErrCodeHandshakeConstraintViolationException for service response error code
	// "HandshakeConstraintViolationException".
	//
	// The requested operation would violate the constraint identified in the reason
	// code.
	//
	//    * ACCOUNT_NUMBER_LIMIT_EXCEEDED: You attempted to exceed the limit on
	//    the number of accounts in an organization. Note: deleted and closed accounts
	//    still count toward your limit.
	//
	// If you get an exception that indicates that you exceeded your account limits
	//    for the organization or that you can"t add an account because your organization
	//    is still initializing, please contact  AWS Customer Support (https://console.aws.amazon.com/support/home#/).
	//
	//    * HANDSHAKE_RATE_LIMIT_EXCEEDED: You attempted to exceed the number of
	//    handshakes you can send in one day.
	//
	//    * ALREADY_IN_AN_ORGANIZATION: The handshake request is invalid because
	//    the invited account is already a member of an organization.
	//
	//    * ORGANIZATION_ALREADY_HAS_ALL_FEATURES: The handshake request is invalid
	//    because the organization has already enabled all features.
	//
	//    * INVITE_DISABLED_DURING_ENABLE_ALL_FEATURES: You cannot issue new invitations
	//    to join an organization while it is in the process of enabling all features.
	//    You can resume inviting accounts after you finalize the process when all
	//    accounts have agreed to the change.
	//
	//    * PAYMENT_INSTRUMENT_REQUIRED: You cannot complete the operation with
	//    an account that does not have a payment instrument, such as a credit card,
	//    associated with it.
	//
	//    * ORGANIZATION_FROM_DIFFERENT_SELLER_OF_RECORD: The request failed because
	//    the account is from a different marketplace than the accounts in the organization.
	//    For example, accounts with India addresses must be associated with the
	//    AISPL marketplace. All accounts in an organization must be from the same
	//    marketplace.
	//
	//    * ORGANIZATION_MEMBERSHIP_CHANGE_RATE_LIMIT_EXCEEDED: You attempted to
	//    change the membership of an account too quickly after its previous change.
	ErrCodeHandshakeConstraintViolationException = "HandshakeConstraintViolationException"

	// ErrCodeHandshakeNotFoundException for service response error code
	// "HandshakeNotFoundException".
	//
	// We can't find a handshake with the HandshakeId that you specified.
	ErrCodeHandshakeNotFoundException = "HandshakeNotFoundException"

	// ErrCodeInvalidHandshakeTransitionException for service response error code
	// "InvalidHandshakeTransitionException".
	//
	// You can't perform the operation on the handshake in its current state. For
	// example, you can't cancel a handshake that was already accepted, or accept
	// a handshake that was already declined.
	ErrCodeInvalidHandshakeTransitionException = "InvalidHandshakeTransitionException"

	// ErrCodeInvalidInputException for service response error code
	// "InvalidInputException".
	//
	// The requested operation failed because you provided invalid values for one
	// or more of the request parameters. This exception includes a reason that
	// contains additional information about the violated limit:
	//
	//    * INVALID_PARTY_TYPE_TARGET: You specified the wrong type of entity (account,
	//    organization, or email) as a party.
	//
	//    * INVALID_SYNTAX_ORGANIZATION_ARN: You specified an invalid ARN for the
	//    organization.
	//
	//    * INVALID_SYNTAX_POLICY_ID: You specified an invalid policy ID.
	//
	//    * INVALID_ENUM: You specified a value that is not valid for that parameter.
	//
	//    * INVALID_FULL_NAME_TARGET: You specified a full name that contains invalid
	//    characters.
	//
	//    * INVALID_LIST_MEMBER: You provided a list to a parameter that contains
	//    at least one invalid value.
	//
	//    * MAX_LENGTH_EXCEEDED: You provided a string parameter that is longer
	//    than allowed.
	//
	//    * MAX_VALUE_EXCEEDED: You provided a numeric parameter that has a larger
	//    value than allowed.
	//
	//    * MIN_LENGTH_EXCEEDED: You provided a string parameter that is shorter
	//    than allowed.
	//
	//    * MIN_VALUE_EXCEEDED: You provided a numeric parameter that has a smaller
	//    value than allowed.
	//
	//    * IMMUTABLE_POLICY: You specified a policy that is managed by AWS and
	//    cannot be modified.
	//
	//    * INVALID_PATTERN: You provided a value that doesn't match the required
	//    pattern.
	//
	//    * INVALID_PATTERN_TARGET_ID: You specified a policy target ID that doesn't
	//    match the required pattern.
	//
	//    * INPUT_REQUIRED: You must include a value for all required parameters.
	//
	//    * INVALID_PAGINATION_TOKEN: Get the value for the NextToken parameter
	//    from the response to a previous call of the operation.
	//
	//    * MAX_FILTER_LIMIT_EXCEEDED: You can specify only one filter parameter
	//    for the operation.
	//
	//    * MOVING_ACCOUNT_BETWEEN_DIFFERENT_ROOTS: You can move an account only
	//    between entities in the same root.
	ErrCodeInvalidInputException = "InvalidInputException"

	// ErrCodeMalformedPolicyDocumentException for service response error code
	// "MalformedPolicyDocumentException".
	//
	// The provided policy document does not meet the requirements of the specified
	// policy type. For example, the syntax might be incorrect. For details about
	// service control policy syntax, see Service Control Policy Syntax (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_scp-syntax.html)
	// in the AWS Organizations User Guide.
	ErrCodeMalformedPolicyDocumentException = "MalformedPolicyDocumentException"

	// ErrCodeMasterCannotLeaveOrganizationException for service response error code
	// "MasterCannotLeaveOrganizationException".
	//
	// You can't remove a master account from an organization. If you want the master
	// account to become a member account in another organization, you must first
	// delete the current organization of the master account.
	ErrCodeMasterCannotLeaveOrganizationException = "MasterCannotLeaveOrganizationException"

	// ErrCodeOrganizationNotEmptyException for service response error code
	// "OrganizationNotEmptyException".
	//
	// The organization isn't empty. To delete an organization, you must first remove
	// all accounts except the master account, delete all organizational units (OUs),
	// and delete all policies.
	ErrCodeOrganizationNotEmptyException = "OrganizationNotEmptyException"

	// ErrCodeOrganizationalUnitNotEmptyException for service response error code
	// "OrganizationalUnitNotEmptyException".
	//
	// The specified organizational unit (OU) is not empty. Move all accounts to
	// another root or to other OUs, remove all child OUs, and then try the operation
	// again.
	ErrCodeOrganizationalUnitNotEmptyException = "OrganizationalUnitNotEmptyException"

	// ErrCodeOrganizationalUnitNotFoundException for service response error code
	// "OrganizationalUnitNotFoundException".
	//
	// We can't find an organizational unit (OU) with the OrganizationalUnitId that
	// you specified.
	ErrCodeOrganizationalUnitNotFoundException = "OrganizationalUnitNotFoundException"

	// ErrCodeParentNotFoundException for service response error code
	// "ParentNotFoundException".
	//
	// We can't find a root or organizational unit (OU) with the ParentId that you
	// specified.
	ErrCodeParentNotFoundException = "ParentNotFoundException"

	// ErrCodePolicyInUseException for service response error code
	// "PolicyInUseException".
	//
	// The policy is attached to one or more entities. You must detach it from all
	// roots, organizational units (OUs), and accounts before performing this operation.
	ErrCodePolicyInUseException = "PolicyInUseException"

	// ErrCodePolicyNotAttachedException for service response error code
	// "PolicyNotAttachedException".
	//
	// The policy isn't attached to the specified target in the specified root.
	ErrCodePolicyNotAttachedException = "PolicyNotAttachedException"

	// ErrCodePolicyNotFoundException for service response error code
	// "PolicyNotFoundException".
	//
	// We can't find a policy with the PolicyId that you specified.
	ErrCodePolicyNotFoundException = "PolicyNotFoundException"

	// ErrCodePolicyTypeAlreadyEnabledException for service response error code
	// "PolicyTypeAlreadyEnabledException".
	//
	// The specified policy type is already enabled in the specified root.
	ErrCodePolicyTypeAlreadyEnabledException = "PolicyTypeAlreadyEnabledException"

	// ErrCodePolicyTypeNotAvailableForOrganizationException for service response error code
	// "PolicyTypeNotAvailableForOrganizationException".
	//
	// You can't use the specified policy type with the feature set currently enabled
	// for this organization. For example, you can enable service control policies
	// (SCPs) only after you enable all features in the organization. For more information,
	// see Enabling and Disabling a Policy Type on a Root (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies.html#enable_policies_on_root)
	// in the AWS Organizations User Guide.
	ErrCodePolicyTypeNotAvailableForOrganizationException = "PolicyTypeNotAvailableForOrganizationException"

	// ErrCodePolicyTypeNotEnabledException for service response error code
	// "PolicyTypeNotEnabledException".
	//
	// The specified policy type is not currently enabled in this root. You cannot
	// attach policies of the specified type to entities in a root until you enable
	// that type in the root. For more information, see Enabling All Features in
	// Your Organization (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html)
	// in the AWS Organizations User Guide.
	ErrCodePolicyTypeNotEnabledException = "PolicyTypeNotEnabledException"

	// ErrCodeRootNotFoundException for service response error code
	// "RootNotFoundException".
	//
	// We can't find a root with the RootId that you specified.
	ErrCodeRootNotFoundException = "RootNotFoundException"

	// ErrCodeServiceException for service response error code
	// "ServiceException".
	//
	// AWS Organizations can't complete your request because of an internal service
	// error. Try again later.
	ErrCodeServiceException = "ServiceException"

	// ErrCodeSourceParentNotFoundException for service response error code
	// "SourceParentNotFoundException".
	//
	// We can't find a source root or OU with the ParentId that you specified.
	ErrCodeSourceParentNotFoundException = "SourceParentNotFoundException"

	// ErrCodeTargetNotFoundException for service response error code
	// "TargetNotFoundException".
	//
	// We can't find a root, OU, or account with the TargetId that you specified.
	ErrCodeTargetNotFoundException = "TargetNotFoundException"

	// ErrCodeTooManyRequestsException for service response error code
	// "TooManyRequestsException".
	//
	// You've sent too many requests in too short a period of time. The limit helps
	// protect against denial-of-service attacks. Try again later.
	ErrCodeTooManyRequestsException = "TooManyRequestsException"
)