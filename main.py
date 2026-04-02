#!/usr/bin/env python3

import argparse
import io
import os
import sys
import tarfile
import docker

INJECTED_BIN_CONTAINER_PATH = "/inject-bin"

def put_file(container, host_path: str, container_path: str) -> None:
    data = io.BytesIO()
    container_dir = os.path.dirname(container_path) or "/"
    arcname = os.path.basename(container_path)
    with tarfile.open(fileobj=data, mode="w") as tar:
        tar.add(host_path, arcname=arcname)
    data.seek(0)
    ok = container.put_archive(container_dir, data.read())
    if not ok:
        raise RuntimeError("docker put_archive returned false")


def exec_in_container(client: docker.DockerClient, container_id: str, cmd: list[str]) -> tuple[int, str]:
    exec_id = client.api.exec_create(container_id, cmd=cmd)["Id"]
    output = client.api.exec_start(exec_id, demux=False)
    inspect = client.api.exec_inspect(exec_id)
    text = output.decode("utf-8", errors="replace") if isinstance(output, (bytes, bytearray)) else str(output)
    return int(inspect.get("ExitCode") or 0), text.strip()


def is_gvisor_runtime(runtime: str, runtime_match: str) -> bool:
    if not runtime:
        return False
    return runtime == runtime_match or runtime_match in runtime


def watch(args: argparse.Namespace) -> int:
    if not os.path.exists(args.inject_bin):
        raise RuntimeError(f"Binary to inject not found at {args.inject_bin}")

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
            print(repr(runtime))
            if not is_gvisor_runtime(runtime, args.runtime_match):
                continue

            print(f"gVisor container {container_id} joined network {network_id}; running injected bin")
            put_file(container, args.inject_bin, INJECTED_BIN_CONTAINER_PATH)
            code, output = exec_in_container(client, container_id, [INJECTED_BIN_CONTAINER_PATH])
            if output:
                print(output)
            if code != 0:
                raise RuntimeError(f"injected bin exited with {code}")

            # Best-effort delete in case self-delete did not happen.
            # exec_in_container(client, container_id, ["rm", "-f", INJECTED_BIN_CONTAINER_PATH])
        except Exception as exc:  # pylint: disable=broad-except
            print(f"failed handling container {container_id}: {exc}")
        finally:
            inflight.discard(key)

    stream.close()
    client.close()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watch Docker network connect events and run legacy iptables injector in gVisor containers."
    )
    parser.add_argument("--inject-bin", help="Path to binary to inject")
    parser.add_argument("--runtime-match", default="runsc", help="Runtime name to match")
    return parser.parse_args()


def main() -> int:
    return watch(parse_args())

if __name__ == "__main__":
    sys.exit(main())
