{application, 'dns_resolver', [
	{description, "DNS resolver"},
	{vsn, "rolling"},
	{modules, ['dns_request_handler','dns_resolver_app','dns_resolver_sup']},
	{registered, [dns_resolver_sup]},
	{applications, [kernel,stdlib,cowboy]},
	{optional_applications, []},
	{mod, {dns_resolver_app, []}},
	{env, []}
]}.