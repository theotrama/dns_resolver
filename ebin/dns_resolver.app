{application, 'dns_resolver', [
	{description, "DNS resolver"},
	{vsn, "rolling"},
	{modules, ['dns_request_handler','dns_resolver_app','dns_resolver_sup','resolver']},
	{registered, [dns_resolver_sup]},
	{applications, [kernel,stdlib,cowboy,jsx]},
	{optional_applications, []},
	{mod, {dns_resolver_app, []}},
	{env, []}
]}.