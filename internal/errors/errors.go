// Package errors implements the exit-code-bearing error type used across the
// CLI so usage errors, unsupported capabilities and interrupts never masquerade
// as runtime failures.
package errors

import "fmt"

// ExitError carries a process exit code alongside a message.
type ExitError struct {
	Code    int
	Message string
	Cause   error
}

func (e *ExitError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *ExitError) Unwrap() error { return e.Cause }

// NewExitError builds an ExitError with the given exit code and message.
func NewExitError(code int, message string) *ExitError {
	return &ExitError{Code: code, Message: message}
}

// WrapExitError wraps a cause into an ExitError with the given code and context.
func WrapExitError(code int, message string, cause error) *ExitError {
	return &ExitError{Code: code, Message: message, Cause: cause}
}
