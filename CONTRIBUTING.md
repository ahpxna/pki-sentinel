# Contributing

## Local dev setup

1. Install Docker, Docker Compose v2, `terraform` >= 1.9, `go` >= 1.22.
2. `cp .env.example .env`
3. `make up` then `make bootstrap`.

## Commit convention

This repo uses [Conventional Commits](https://www.conventionalcommits.org/):
`feat(phase1): create intermediate CA via terraform`, `fix(probe): correct OCSP staple timing`, etc.
One logical step per commit.

## Code style

- Go: `gofmt`, `golangci-lint run` before pushing.
- Terraform: `terraform fmt -recursive`.
- Shell: `shellcheck`.
