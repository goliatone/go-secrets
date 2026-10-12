//go:build !darwin

package keychain

func platformSupported() bool { return false }
