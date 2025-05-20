# OpenAI Codex Instructions

- On startup, run `go mod download`
- Run `GOOS=linux GOARCH=amd64 go test ./...`, `GOOS=windows GOARCH=amd64 go test ./...`, and `GOOS=darwin GOARCH=amd64 go test ./...` after all changes to ensure tests pass on all platforms
- Always include tests for new functionality
- Update documentation when necessary for changes
- Consider all platforms (Windows, Linux, Mac) when making changes
