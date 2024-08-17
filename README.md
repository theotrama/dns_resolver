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

## Website
To run the browser resolver tool. Afterward, go to http://localhost:8080/static.
```bash
make run # from root directory
```
