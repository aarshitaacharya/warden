// RBAC: roles map to actions. Default deny for anything not listed.
@id("rbac-employee")
permit(principal in Role::"employee",
       action in [Action::"tickets:create", Action::"docs:read", Action::"comms:send_email"],
       resource);

@id("rbac-engineer")
permit(principal in Role::"engineer",
       action in [Action::"tickets:read", Action::"tickets:update", Action::"docs:write", Action::"comms:http_post"],
       resource);

@id("rbac-hr")
permit(principal in Role::"hr",
       action in [Action::"hr:read_record", Action::"hr:update_record", Action::"tickets:read"],
       resource);

@id("rbac-finance")
permit(principal in Role::"finance",
       action in [Action::"finance:read_report", Action::"finance:create_payment"],
       resource);

@id("rbac-manager")
permit(principal in Role::"manager",
       action in [Action::"tickets:read", Action::"tickets:delete"],
       resource);
