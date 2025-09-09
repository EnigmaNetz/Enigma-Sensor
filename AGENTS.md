# Agent Instructions

Read CLAUDE.md for complete project context and follow all guidelines there.

## Setup Requirements (Remote Execution)

Before running any code, ensure the following setup is complete:

### Go Service (sensor)
```bash
go mod download
go test -i ./...
```

## Agent Guidelines
- Always verify environment setup before running code
- Include setup verification in code execution
- Test commands in the appropriate service directory
- Run cross-platform tests before any code changes
- Consider all platforms (Windows, Linux, Mac) when making changes
- Follow existing code patterns and conventions
- Never use git add . - stage files explicitly
- Use present tense in commit messages
