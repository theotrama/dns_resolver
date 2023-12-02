{application, 'dns_resolver', [
	{description, "New project"},
	{vsn, "0.1.0"},
	{modules, ['dns_resolver_app','dns_resolver_sup']},
	{registered, [dns_resolver_sup]},
	{applications, [kernel,stdlib]},
	{optional_applications, []},
	{mod, {dns_resolver_app, []}},
	{env, []}
]}.