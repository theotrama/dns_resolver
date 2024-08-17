# DNS Resolver
A recursive DNS resolver written in Erlang.
## How to run
Go into src/ directory and start erl. Then run the resolver providing a domain.
```bash
cd src/
erl
```

```bash
c(resolver).
resolver:run("google.com").
```