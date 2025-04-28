# Cursor Rules for Enigma Go Agent

## Code Style & Linting
- All code must be formatted with `gofmt` and `goimports`.
- Use `golangci-lint` with at least: `govet`, `staticcheck`, `errcheck`, `ineffassign`, `gosec`, `gocritic`.
- Consistent naming: `CamelCase` for exported, `camelCase` for locals, ALL_CAPS for constants.
- No unused code, variables, or imports.

## Project Structure
- Use idiomatic Go layout: `cmd/`, `pkg/`, `internal/`, `scripts/`.
- Keep `main.go` minimal; business logic in packages.

## Error Handling
- Always check and handle errors. Never ignore returned errors.
- Wrap errors with context using `fmt.Errorf` or similar.

## Security
- Never log API keys or secrets. Redact sensitive data in logs.
- Set config/log/data file permissions to `0600` or stricter.
- Validate all user/config input.

## Testing
- All new logic must have unit tests (`*_test.go`).
- Use mocks for external dependencies (gRPC, file system).
- No code merges with failing tests or linter errors.

## Documentation
- All exported functions/types must have GoDoc comments.
- Keep README up to date with install, config, and migration instructions.

## Review & CI
- PRs should be small and focused.
- Address all linter and reviewer comments before merging.
- CI must run lint, test, and build on every PR/commit.

## Cross-Platform
- No OS-specific code in core logic. Use build tags or adapters for platform differences.
- Test on both Windows and Linux.