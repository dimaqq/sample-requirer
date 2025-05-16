package main

import (
	"context"

	"github.com/gruyaume/goops"
	"github.com/dimaqq/sample-requirer/internal/charm"
)

const (
	serviceName            = "notary-k8s"
)

func main() {
	hc := goops.NewHookContext()
	hook := hc.Environment.JujuHookName()

	if hook == "" {
		return
	}

	run(hc, hook)
}

func run(hc *goops.HookContext, hook string) {
	ctx := context.Background()

	charm.HandleDefaultHook(ctx, hc)
	charm.SetStatus(ctx, hc)
}
