package main

import (
	"encoding/json"
	"fmt"
	"os"

	"capability-broker/redteam"
)

func main() {
	scenarios, err := redteam.LoadEmbedded()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	rep, err := redteam.RunAll(scenarios)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(rep.Headline())
	fmt.Println()
	fmt.Println(rep.Table())
	if os.Getenv("REDTEAM_JSON") == "1" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	}
	if err := redteam.FailCI(rep); err != nil {
		fmt.Fprintln(os.Stderr, "CI gate:", err)
		os.Exit(1)
	}
}
