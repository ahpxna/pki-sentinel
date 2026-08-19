# Contributing

## Local dev setup

Install Docker, Docker Compose v2, Terraform 1.9.5, and Go 1.26.5, then:

```bash
cp .env.example .env
make up
make bootstrap
```

## Commit convention

This repo uses [Conventional Commits](https://www.conventionalcommits.org/):
`feat(phase1): create intermediate CA via terraform`, `fix(probe): correct OCSP staple timing`, etc.
One logical step per commit.

## Code style

- Go: `gofmt`, `golangci-lint run` before pushing.
- Terraform: `terraform fmt -recursive`.
- Shell: `shellcheck`.
