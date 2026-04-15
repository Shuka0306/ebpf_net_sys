// Package cache implements the user-space DNS cache used by the DNS baseline.
//
// It stores structured DNS records keyed by QName + QType and supports TTL-
// based expiration plus a simple capacity eviction policy.
package cache

