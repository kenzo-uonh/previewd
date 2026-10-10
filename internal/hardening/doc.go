// Package hardening verifies and applies process-level protections. It is a
// leaf: it imports no internal package. Platform code lives in _linux.go /
// _other.go pairs; on other platforms every protection fails closed.
package hardening
