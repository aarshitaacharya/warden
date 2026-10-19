// ReBAC: access follows relationships in the org graph.
@id("rebac-manager-reads-reports-hr")
permit(principal, action == Action::"hr:read_record", resource is HRRecord)
when { resource.subject_manager == principal };

@id("rebac-self-reads-own-hr")
permit(principal, action == Action::"hr:read_record", resource is HRRecord)
when { resource.subject == principal };
