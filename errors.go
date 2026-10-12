package secrets

import (
	"context"
	"errors"
	"reflect"
)

// ErrorKind classifies failures without exposing provider output.
type ErrorKind string

const (
	ErrorInvalidReference       ErrorKind = "invalid_reference"
	ErrorUnsupportedProvider    ErrorKind = "unsupported_provider"
	ErrorNotFound               ErrorKind = "not_found"
	ErrorUnavailable            ErrorKind = "unavailable"
	ErrorTemporary              ErrorKind = "temporary"
	ErrorAuthenticationRequired ErrorKind = "authentication_required"
	ErrorPermissionDenied       ErrorKind = "permission_denied"
	ErrorInvalidSecret          ErrorKind = "invalid_secret"
	ErrorDisabled               ErrorKind = "disabled"
	ErrorConflict               ErrorKind = "conflict"
	ErrorPolicyDenied           ErrorKind = "policy_denied"
	ErrorInternal               ErrorKind = "internal"
	ErrorCanceled               ErrorKind = "canceled"
	ErrorDeadlineExceeded       ErrorKind = "deadline_exceeded"
)

// Error is safe to return through logs and transports. Cause must itself be
// sanitized before it is attached.
type Error struct {
	Kind    ErrorKind
	Op      string
	Message string
	Field   string
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Op != "" {
		return e.Op + ": " + string(e.Kind)
	}
	return string(e.Kind)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func NewError(kind ErrorKind, op, message string) *Error {
	return &Error{Kind: kind, Op: op, Message: message}
}

func NewFieldError(kind ErrorKind, op, message, field string) *Error {
	return &Error{Kind: kind, Op: op, Message: message, Field: field}
}

func WrapError(kind ErrorKind, op, message string, cause error) *Error {
	return &Error{Kind: kind, Op: op, Message: message, Cause: cause}
}

func KindOf(err error) ErrorKind {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return ErrorCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorDeadlineExceeded
	}
	if target, ok := errors.AsType[*Error](err); ok {
		return target.Kind
	}
	return ErrorInternal
}

func IsKind(err error, kind ErrorKind) bool { return KindOf(err) == kind }

func FieldOf(err error) string {
	if target, ok := errors.AsType[*Error](err); ok {
		return target.Field
	}
	return ""
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
