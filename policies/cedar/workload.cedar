// Services and agents authorize through the scopes in their token.
@id("service-scope")
permit(principal is Service, action, resource)
when { principal.scopes.contains(context.action_id) };

@id("agent-scope")
permit(principal is Agent, action, resource)
when { principal.scopes.contains(context.action_id) };

// Agents may never perform destructive actions, whatever their scopes say.
@id("agent-no-destructive")
forbid(principal is Agent,
       action in [Action::"tickets:delete", Action::"hr:delete_record"],
       resource);
