#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import docker

BUILTIN_NETWORKS = {"bridge", "host", "none"}


# Find the gateway and container IP of the first custom Docker network.
def find_custom_gateway(container) -> tuple[str, str]:
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    for name, cfg in networks.items():
        if name in BUILTIN_NETWORKS:
            continue
        gateway = cfg.get("Gateway")
        container_ip = cfg.get("IPAddress")
        if gateway and container_ip:
            return gateway, container_ip
    raise RuntimeError("no custom network with a gateway found")


# Write /etc/resolv.conf inside the container pointing at the given nameserver.
def inject_resolv_conf(client: docker.DockerClient, container_id: str, gateway_ip: str) -> None:
    cmd = ["sh", "-c", f"echo 'nameserver {gateway_ip}' > /etc/resolv.conf"]
    exec_id = client.api.exec_create(container_id, cmd=cmd)["Id"]
    output = client.api.exec_start(exec_id, demux=False)
    inspect = client.api.exec_inspect(exec_id)
    exit_code = int(inspect.get("ExitCode") or 0)
    if exit_code != 0:
        text = output.decode("utf-8", errors="replace") if isinstance(output, (bytes, bytearray)) else str(output)
        raise RuntimeError(f"writing resolv.conf failed (exit {exit_code}): {text}")


# Run setup_lo.sh in the container's network namespace via nsenter.
def run_setup_lo(container, setup_lo_path: str, gateway_ip: str, container_ip: str) -> None:
    pid = container.attrs["State"]["Pid"]
    if not pid:
        raise RuntimeError("container has no PID")
    result = subprocess.run(
        ["nsenter", "-t", str(pid), "-n", "--", setup_lo_path, gateway_ip, container_ip],
        capture_output=True, text=True,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"setup_lo.sh exited with {result.returncode}")


# Watch Docker events and configure DNS for new gVisor containers.
def watch(args: argparse.Namespace) -> int:
    setup_lo_path = os.path.abspath(args.setup_lo)
    if not os.path.exists(setup_lo_path):
        raise RuntimeError(f"setup_lo.sh not found at {setup_lo_path}")

    client = docker.from_env()
    inflight: set[tuple[str, str]] = set()

    print("listening for Docker network connect events")
    stream = client.events(decode=True, filters={"type": ["network"], "event": ["connect"]})

    for event in stream:
        actor = event.get("Actor", {})
        attrs = actor.get("Attributes", {})
        container_id = attrs.get("container")
        network_id = actor.get("ID") or "unknown-network"
        if not container_id:
            continue

        key = (container_id, network_id)
        if key in inflight:
            continue
        inflight.add(key)

        try:
            container = client.containers.get(container_id)
            runtime = (container.attrs.get("HostConfig") or {}).get("Runtime", "")
            if runtime != args.runtime_match:
                continue

            gateway_ip, container_ip = find_custom_gateway(container)
            print(f"gVisor container {container_id[:12]} joined network {network_id[:12]}; "
                  f"gateway={gateway_ip} container_ip={container_ip}")

            inject_resolv_conf(client, container_id, gateway_ip)
            print(f"  injected /etc/resolv.conf with nameserver {gateway_ip}")

            run_setup_lo(container, setup_lo_path, gateway_ip, container_ip)
            print(f"  ran setup_lo.sh successfully")
        except Exception as exc:
            print(f"failed handling container {container_id}: {exc}")
        finally:
            inflight.discard(key)

    stream.close()
    client.close()
    return 0


# Parse command-line arguments.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch Docker network connect events and configure DNS for gVisor containers."
    )
    parser.add_argument("--setup-lo", default="./setup_lo.sh", help="Path to setup_lo.sh script")
    parser.add_argument("--runtime-match", default="runsc", help="Runtime name to match")
    return parser.parse_args()


def main() -> int:
    return watch(parse_args())

if __name__ == "__main__":
    sys.exit(main())
