package subprocess

import (
	"bytes"
	"context"
	"os/exec"
)

type Result struct {
	Stdout         []byte
	Stderr         []byte
	OutputExceeded bool
}

type Runner interface {
	Run(context.Context, string, []string, []string, int) (Result, error)
}

type RunnerFunc func(context.Context, string, []string, []string, int) (Result, error)

func (f RunnerFunc) Run(ctx context.Context, executable string, args, environment []string, limit int) (Result, error) {
	return f(ctx, executable, args, environment, limit)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, args, environment []string, limit int) (Result, error) {
	if limit <= 0 {
		limit = 64 << 10
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: limit}
	command := exec.CommandContext(ctx, executable, args...) // #nosec G204 -- providers own the executable and fixed argument shape.
	command.Env = append([]string(nil), environment...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), OutputExceeded: stdout.exceeded || stderr.exceeded}, err
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (w *limitedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := w.limit + 1 - w.buffer.Len()
	if remaining > 0 {
		if remaining < len(value) {
			value = value[:remaining]
		}
		_, _ = w.buffer.Write(value)
	}
	if w.buffer.Len() > w.limit || len(value) < written {
		w.exceeded = true
	}
	return written, nil
}

func (w *limitedBuffer) Bytes() []byte { return append([]byte(nil), w.buffer.Bytes()...) }
