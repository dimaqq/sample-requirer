package main

import (
	"context"

	"github.com/gruyaume/goops"
	"github.com/dimaqq/sample-requirer/internal/charm"
)

func main() {
	hc := goops.NewHookContext()
	hook := hc.Environment.JujuHookName()

	if hook == "" {
		return
	}

	run(hc)
}

func run(hc *goops.HookContext) {
	ctx := context.Background()

	charm.HandleDefaultHook(ctx, hc)
	charm.SetStatus(ctx, hc)
}
