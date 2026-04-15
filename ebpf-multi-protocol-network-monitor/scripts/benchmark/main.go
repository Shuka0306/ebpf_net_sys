package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "benchmark launcher: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	root, err := findModuleRoot()
	if err != nil {
		return err
	}

	cmdArgs := append([]string{"run", "./services/dns/cmd/dnsbench"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	cmd.Dir = root
	return cmd.Run()
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("benchmark launcher: could not find go.mod")
		}
		dir = parent
	}
}
