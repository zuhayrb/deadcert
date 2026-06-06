# Deadcert - SSL Certificate Expiration Checker

## Project Overview
A CLI tool that checks SSL certificate expiration dates for given domains, with concurrent checking capabilities and both human-readable and JSON output formats.

## Learning Objectives
- Network programming with Go's crypto/tls package
- Error handling for various connection failure scenarios
- Concurrency implementation using goroutines and sync.WaitGroup
- Structured output (human-readable and JSON)
- Command-line flag handling with Cobra
- Testing approaches for network-dependent code

## Technical Requirements
- Connect to domains via TLS
- Parse certificate expiration dates
- Concurrent domain checking
- Human-readable output with color coding
- JSON output mode
- Configurable timeout values
- Support for multiple domain inputs

## Project Structure
```
deadcert/
├── cmd/
│   └── deadcert/
│       └── main.go
├── internal/
│   ├── certcheck/
│   │   ├── checker.go
│   │   └── checker_test.go
│   ├── output/
│   │   ├── formatter.go
│   │   └── formatter_test.go
│   └── config/
│       └── config.go
├── pkg/
│   └── utils/
│       └── utils.go
├── main.go
├── go.mod
└── README.md
```

## Implementation Phases

### Phase 1: Basic Sequential Version
- Single domain checking capability
- Basic TLS connection and certificate parsing
- Simple text output
- Command-line argument parsing

### Phase 2: Multiple Domains & Concurrency
- Handle multiple domain inputs
- Implement concurrent checking with goroutines
- Add WaitGroup for synchronization
- Basic error handling for connection issues

### Phase 3: Enhanced Features
- Color-coded output for different expiration statuses
- JSON output option
- Configurable timeouts
- Improved error categorization and reporting

### Phase 4: Refinement & Polish
- Comprehensive error handling for all edge cases
- Unit and integration tests
- Documentation and examples
- Performance optimizations

## Success Criteria
- Successfully identifies expired certificates
- Handles various error conditions gracefully
- Provides clear, actionable output
- Performs concurrent checks efficiently
- Includes proper documentation and examples
