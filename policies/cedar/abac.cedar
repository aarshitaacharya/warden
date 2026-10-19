// ABAC: context and data labels. Forbid always overrides permit.
@id("abac-risk-deny")
forbid(principal, action, resource)
when { context.risk_score >= 80 };

@id("abac-restricted-needs-trusted-device")
forbid(principal, action, resource)
when { resource has sensitivity && resource.sensitivity >= 3 && !context.device_trusted };

@id("abac-payments-need-stepup")
forbid(principal, action == Action::"finance:create_payment", resource)
when { !context.stepped_up };

@id("abac-hr-writes-need-stepup")
forbid(principal, action in [Action::"hr:update_record", Action::"hr:delete_record"], resource)
when { !context.stepped_up };

@id("abac-confidential-business-hours")
forbid(principal is User, action, resource)
when { resource has sensitivity && resource.sensitivity >= 2 && !context.business_hours };
