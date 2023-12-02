PROJECT = dns_resolver
PROJECT_DESCRIPTION = DNS resolver

BUILD_DEPS += relx
DEPS = cowboy
DEPS += jsx
dep_cowboy_commit = 2.10.0

DEP_PLUGINS = cowboy

include erlang.mk