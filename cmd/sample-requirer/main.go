package main

import (
	"context"

	"github.com/gruyaume/goops"
	"github.com/dimaqq/sample-requirer/internal/charm"
)

const (
	serviceName            = "notary-k8s"
	TracingIntegrationName = "tracing"
)

func main() {
	hc := goops.NewHookContext()
	hook := hc.Environment.JujuHookName()

	if hook == "" {
		return
	}

	run(hc, hook)
}

// run initializes tracing, starts the root span, dispatches hooks, and ensures shutdown.
func run(hc *goops.HookContext, hook string) {
	ctx := context.Background()

	charm.HandleDefaultHook(ctx, hc)
	charm.SetStatus(ctx, hc)
}
