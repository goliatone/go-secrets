// Package secrets provides safe, provider-qualified secret references and
// short-lived secret values. It deliberately excludes persistence, transport,
// and concrete provider dependencies so applications can compose those at
// their trusted I/O boundaries.
package secrets
