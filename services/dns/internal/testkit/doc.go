// Package testkit provides the utility layer for DNS baseline development.
//
// It is intentionally split into small focused subpackages so the project can
// grow in a test-driven and performance-oriented way:
//   - loadgen: repeatable DNS traffic generation
//   - profiler: pprof capture and profiling helpers
//   - report: benchmark result collection and export
//   - assert: response correctness checks
//   - benchcmp: baseline vs optimized comparison helpers
package testkit

