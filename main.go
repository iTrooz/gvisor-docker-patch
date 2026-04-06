package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const SETUP_NETNS_SCRIPT = "./setup_netns.sh"

var builtinNetworks = map[string]struct{}{
	"bridge": {},
	"host":   {},
	"none":   {},
}

type eventKey struct {
	containerID string
	networkID   string
}

// findNetworkGateway finds the gateway and container IP for the first custom Docker network.
func findNetworkGateway(inspect container.InspectResponse) (string, string, error) {
	if inspect.NetworkSettings == nil {
		return "", "", errors.New("container has no network settings")
	}

	for name, cfg := range inspect.NetworkSettings.Networks {
		if _, isBuiltin := builtinNetworks[name]; isBuiltin {
			continue
		}
		if cfg != nil && cfg.Gateway != "" && cfg.IPAddress != "" {
			return cfg.Gateway, cfg.IPAddress, nil
		}
	}

	return "", "", errors.New("no custom network with a gateway found")
}

// injectResolvConf writes /etc/resolv.conf inside the container with the provided nameserver.
func injectResolvConf(ctx context.Context, cli *client.Client, containerID, gatewayIP string) error {
	cmd := []string{"sh", "-c", fmt.Sprintf("echo 'nameserver %s' > /etc/resolv.conf", gatewayIP)}

	execResp, err := cli.ContainerExecCreate(ctx, containerID, container.ExecOptions{Cmd: cmd})
	if err != nil {
		return fmt.Errorf("create exec: %w", err)
	}

	attach, err := cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("start/attach exec: %w", err)
	}
	defer attach.Close()

	output, _ := io.ReadAll(attach.Reader)

	inspectResp, err := cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return fmt.Errorf("inspect exec: %w", err)
	}
	if inspectResp.ExitCode != 0 {
		return fmt.Errorf("writing resolv.conf failed (exit %d): %s", inspectResp.ExitCode, strings.TrimSpace(string(output)))
	}

	return nil
}

// setupNetNs runs setup_netns.sh in the container network namespace via nsenter.
func setupNetNs(pid int, gatewayIP, containerIP string) error {
	if pid == 0 {
		return errors.New("container has no PID")
	}

	cmd := exec.Command("nsenter", "-t", fmt.Sprintf("%d", pid), "-n", "--", SETUP_NETNS_SCRIPT, gatewayIP, containerIP)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("netns setup script exited with %d", exitErr.ExitCode())
		}
		return fmt.Errorf("netns setup script: %w", err)
	}

	return nil
}

// watch listens for Docker network connect events and configures matching containers.
func watch(runtimeMatch string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("create docker client: %w", err)
	}

	inflight := make(map[eventKey]struct{})

	fmt.Println("listening for Docker network connect events")
	f := filters.NewArgs(filters.Arg("type", "network"), filters.Arg("event", "connect"))
	msgCh, errCh := cli.Events(ctx, events.ListOptions{Filters: f})

	for {
		select {
		case event, ok := <-msgCh:
			if !ok {
				return nil
			}

			containerID := event.Actor.Attributes["container"]
			networkID := event.Actor.ID
			if networkID == "" {
				networkID = "unknown-network"
			}
			if containerID == "" {
				continue
			}

			key := eventKey{containerID: containerID, networkID: networkID}
			if _, exists := inflight[key]; exists {
				continue
			}
			inflight[key] = struct{}{}

			func() {
				defer delete(inflight, key)

				inspect, err := cli.ContainerInspect(ctx, containerID)
				if err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}

				runtime := ""
				if inspect.HostConfig != nil {
					runtime = inspect.HostConfig.Runtime
				}
				if runtime != runtimeMatch {
					return
				}

				gatewayIP, containerIP, err := findNetworkGateway(inspect)
				if err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}

				fmt.Printf("gVisor container %s joined network %s; gateway=%s container_ip=%s\n", shortID(containerID), shortID(networkID), gatewayIP, containerIP)

				if err := injectResolvConf(ctx, cli, containerID, gatewayIP); err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}
				fmt.Printf("  injected /etc/resolv.conf with nameserver %s\n", gatewayIP)

				if err := setupNetNs(inspect.State.Pid, gatewayIP, containerIP); err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}
				fmt.Println("  ran setup_lo.sh successfully")
			}()

		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("docker events stream error: %w", err)
			}
		}
	}
}

// shortID returns the first 12 chars of an ID for display.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

// parseArgs parses command-line flags.
func parseArgs() string {
	runtimeMatch := flag.String("runtime-match", "runsc", "Runtime name to match")
	flag.Parse()
	return *runtimeMatch
}

// main is the process entrypoint.
func main() {
	runtimeMatch := parseArgs()

	if _, err := os.Stat(SETUP_NETNS_SCRIPT); err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("netns setup script not found at %s", SETUP_NETNS_SCRIPT))
		os.Exit(1)
	}

	if err := watch(runtimeMatch); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
