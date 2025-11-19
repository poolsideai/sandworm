package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/poolsideai/sandworm/pkg/proxy"
)

func main() {
	rootCmd := proxyCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type proxyArgs struct {
	Port         int
	AdminEnabled bool
	Domains      string
	CIDRs        string
	LogLevel     string
}

func proxyCommand() *cobra.Command {
	var args proxyArgs

	cmd := &cobra.Command{
		Use:   "sandworm",
		Short: "Network proxy for sandbox container environments",
		Long: `A network proxy that provides controlled Internet access to sandboxed containers.
		
Intended use: the proxy runs in a container with Internet access and provides HTTP/HTTPS proxy
to containers on an internal network, with configurable domain and CIDR filtering.`,
		RunE: func(cmd *cobra.Command, cmdArgs []string) error {
			return runProxy(args)
		},
	}

	cmd.Flags().IntVarP(&args.Port, "port", "p", 2137, "Proxy port")
	cmd.Flags().BoolVarP(&args.AdminEnabled, "admin", "a", false, "Enable admin panel")
	cmd.Flags().StringVarP(&args.Domains, "domains", "d", "", "Comma-separated list of allowed domains")
	cmd.Flags().StringVarP(&args.CIDRs, "cidrs", "c", "", "Comma-separated list of allowed CIDRs")
	cmd.Flags().StringVarP(&args.LogLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")

	return cmd
}

func runProxy(args proxyArgs) error {
	level := slog.LevelInfo
	switch args.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	var allowedDomains []string
	var allowedCIDRs []string

	if args.Domains != "" {
		allowedDomains = strings.Split(args.Domains, ",")
		for i, domain := range allowedDomains {
			allowedDomains[i] = strings.TrimSpace(domain)
		}
	}

	if args.CIDRs != "" {
		allowedCIDRs = strings.Split(args.CIDRs, ",")
		for i, cidr := range allowedCIDRs {
			allowedCIDRs[i] = strings.TrimSpace(cidr)
		}
	}

	proxyServer := proxy.NewProxy(args.Port, args.AdminEnabled, allowedDomains, allowedCIDRs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := proxyServer.Start(ctx); err != nil {
		slog.Error("Failed to start proxy", "error", err)
		return err
	}

	slog.Info("Proxy started successfully",
		"port", args.Port,
		"admin", args.AdminEnabled,
		"domains", allowedDomains,
		"cidrs", allowedCIDRs)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	slog.Info("Received shutdown signal")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := proxyServer.Stop(); err != nil {
		slog.Error("Error during proxy shutdown", "error", err)
		return err
	}

	<-shutdownCtx.Done()
	slog.Info("Proxy shut down")
	return nil
}