package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog" //consider moving to logrus, maybe a better fit for Cli tooling/flexibility?
	"os"
	"path/filepath"
	"runtime/debug"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mjlshen/mirrosa/pkg/mirrosa"
	"github.com/mjlshen/mirrosa/pkg/tui"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	clusterId := f.String("cluster-id", "", "OCM internal or external cluster id")
	interactive := f.Bool("i", false, "run in an interactive exploratory mode")
	logVerbosity := f.Int("v", 1, "enable verbose logging 0(error),1(warn),2(info),3(debug) default:1(warn)")
	logTime := f.Bool("log-time", false, "enable timestamps in logs")
	logSource := f.Bool("log-source", false, "enable logging of source files full path")

	f.Parse(os.Args[1:])

	// logger handler/callback.
	// truncate source path
	replace := func(groups []string, a slog.Attr) slog.Attr {
		if !*logTime {
			// Remove time.
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
		}
		if !*logSource {
			// Remove the directory from the source's filename.
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)
			}
		}
		return a
	}

	opts := slog.HandlerOptions{}

	switch *logVerbosity {
	case 3:
		opts.Level = slog.LevelDebug
	case 2:
		opts.Level = slog.LevelInfo
	case 1:
		opts.Level = slog.LevelWarn
	case 0:
		opts.Level = slog.LevelError
	default:
		//Assume an int > 3...
		opts.Level = slog.LevelDebug
	}
	if *logVerbosity >= 2 {
		opts.ReplaceAttr = replace
		opts.AddSource = true
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &opts))

	if info, ok := debug.ReadBuildInfo(); ok {
		logger.Debug(fmt.Sprintf("Go Version: %s", info.GoVersion))
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				logger.Debug(fmt.Sprintf("Git SHA: %s", setting.Value))
			}
			if setting.Key == "vcs.time" {
				logger.Debug(fmt.Sprintf("From: %s", setting.Value))
			}
		}
	}

	if *interactive {
		p := tea.NewProgram(tui.InitModel())
		if _, err := p.Run(); err != nil {
			logger.Error(err.Error())
		}
		os.Exit(0)
	}

	if *clusterId == "" {
		logger.Error("cluster id must not be empty")
		os.Exit(1)
	}

	m, err := mirrosa.NewRosaClient(context.Background(), logger, *clusterId)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	logger.Debug("cluster info from OCM", "cluster info", *m.ClusterInfo)
	logger.Info("who's the fairest of them all", "cluster", m.ClusterInfo.Name)

	if err := m.ValidateComponents(context.TODO(),
		// Checks that dns is enabled.
		m.NewVpc(),

		// Checks that dns domains do not have uppercase. Should this include additional checks for custom domains?
		m.NewDhcpOptions(),

		// Security group lookup appears to be incorrect.
		// This could/should iterate all SGs attached to an instance to confirm min rules are applied.
		m.NewSecurityGroup(),

		// Checks for valid vpc endpoint 'if' using privatelink
		m.NewVpcEndpointService(),

		// Check that a public zone matching the cluster basename exists.
		m.NewPublicHostedZone(),

		// Check that a private zone matching "<clustername>.<cluster basename>" exists and is associated with the cluster's VPC ID
		// Check private zone for record prefixes: "api", "api-int". "*.apps", with suffix: "<clustername>.<cluster basename>"
		// Verify each record is an "A" record, and alias is set to 'true/yes'
		m.NewPrivateHostedZone(),

		//Check that the internal and external load balancers are present matching "<cluster.infra_id>-int" and "<cluster.infra_id>-ext"
		m.NewApiLoadBalancer(),

		//Find instances belonging to the cluster with tag matching: 'kubernetes.io/cluster/<cluster.infra_id>:"owned"'
		//Find '3' master node instances with tag value matching: '<cluster.infra_id>-master'.
		// (This could be improved to find a specific tag/key, and use regex to match the trailing master-0, master-1, maseter-3, etc..)
		// Check that master instances are running
		// Check that each master node has exactly '1' security group associated with it.
		// (this can be expanded to actually validate the security group further)
		// Next check infra and worker instances matching tag value matching: '<cluster.infra_id>-infra' and <cluster.infra_id>-worker'
		// - at least >= 3 infra instances for multi-AZ clusters, >= 2 instances for single AZ
		// - at least >= 1 worker instance
		// Check all  instances for running and exactly 1 security group.
		m.NewInstances(),
	); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	logger.Info("No issues found")
	logger.Info(fmt.Sprintf("%s is the fairest of them all!", m.ClusterInfo.Name))
	os.Exit(0)
}
