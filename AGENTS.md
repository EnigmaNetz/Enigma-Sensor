# OpenAI Codex Instructions

- On startup, run `go mod download` and `go test -i ./...` to download everything you need
- Run `GOOS=linux GOARCH=amd64 go test ./...`, `GOOS=windows GOARCH=amd64 go test ./...`, and `GOOS=darwin GOARCH=amd64 go test ./...` after all changes to ensure tests pass on all platforms
- Consider all platforms (Windows, Linux, Mac) when making changes
- Refer to `.cursor/rules/rules.md` for additional rules
