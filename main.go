package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const SETUP_NETNS_SCRIPT = "./setup_netns.sh"
const HOST_MOUNT_PATH = "/mnt"

var builtinNetworks = map[string]struct{}{
	"bridge": {},
	"host":   {},
	"none":   {},
}

type eventKey struct {
	containerID string
}

// findFirstCustomNetwork finds the first custom Docker network details.
func findFirstCustomNetwork(inspect container.InspectResponse) (string, string, string, string, error) {
	if inspect.NetworkSettings == nil {
		return "", "", "", "", errors.New("container has no network settings")
	}

	networkNames := make([]string, 0, len(inspect.NetworkSettings.Networks))
	for name := range inspect.NetworkSettings.Networks {
		networkNames = append(networkNames, name)
	}
	// Sort for deterministic behavior
	sort.Strings(networkNames)

	for _, name := range networkNames {
		cfg := inspect.NetworkSettings.Networks[name]
		if _, isBuiltin := builtinNetworks[name]; isBuiltin {
			continue
		}
		if cfg != nil && cfg.Gateway != "" && cfg.IPAddress != "" && cfg.MacAddress != "" {
			return name, cfg.Gateway, cfg.IPAddress, cfg.MacAddress, nil
		}
	}

	return "", "", "", "", errors.New("no custom network with gateway/ip/mac found")
}

// injectResolvConf writes the container resolv.conf through its host ResolvConfPath.
func injectResolvConf(hostResolvConfPath, gatewayIP string) error {
	ctHostResolvConfPath := path.Join(HOST_MOUNT_PATH, hostResolvConfPath)
	content := []byte(fmt.Sprintf("# Written by gvisor-docker-patch\nnameserver %s\n", gatewayIP))
	if err := os.WriteFile(ctHostResolvConfPath, content, 0644); err != nil {
		return fmt.Errorf("write resolv.conf at %s: %w", ctHostResolvConfPath, err)
	}

	return nil
}

// setupNetNs runs setup_netns.sh in the container network namespace via nsenter.
func setupNetNs(pid int, gatewayIP, containerIP, containerMAC string) error {
	if pid == 0 {
		return errors.New("container has no PID")
	}

	cmd := exec.Command("nsenter", "-t", fmt.Sprintf("%d", pid), "-n", "--", SETUP_NETNS_SCRIPT, gatewayIP, containerIP, containerMAC)
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

// watch listens for Docker container start events and configures matching containers.
func watch(runtimeMatch string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("create docker client: %w", err)
	}

	inflight := make(map[eventKey]struct{})

	fmt.Println("listening for Docker container start events")
	f := filters.NewArgs(filters.Arg("type", "container"), filters.Arg("event", "start"))
	msgCh, errCh := cli.Events(ctx, events.ListOptions{Filters: f})

	for {
		select {
		case event, ok := <-msgCh:
			if !ok {
				return nil
			}

			containerID := event.Actor.ID
			if containerID == "" {
				continue
			}

			key := eventKey{containerID: containerID}
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

				networkName, gatewayIP, containerIP, containerMAC, err := findFirstCustomNetwork(inspect)
				if err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}

				fmt.Printf("gVisor container %s started on network %s; gateway=%s container_ip=%s container_mac=%s\n", shortID(containerID), networkName, gatewayIP, containerIP, containerMAC)

				if err := injectResolvConf(inspect.ResolvConfPath, gatewayIP); err != nil {
					fmt.Printf("failed handling container %s: %v\n", containerID, err)
					return
				}
				fmt.Printf("  injected /etc/resolv.conf with nameserver %s\n", gatewayIP)

				if err := setupNetNs(inspect.State.Pid, gatewayIP, containerIP, containerMAC); err != nil {
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

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "must run as root")
		os.Exit(1)
	}

	if _, err := os.Stat(SETUP_NETNS_SCRIPT); err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("netns setup script not found at %s", SETUP_NETNS_SCRIPT))
		os.Exit(1)
	}

	if err := watch(runtimeMatch); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
