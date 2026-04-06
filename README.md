# gvisor-docker-patch

This project allows Docker containers runtime within the [gVisor](https://gvisor.dev/) runtime to use DNS to discover themselves/access Internet, when running a custom network (such as when using docker-compose). It solves https://github.com/google/gvisor/issues/7469.

# How to use
Just run the following [compose file](./compose.yml) in your server, and re-create your gVisor-based containers. They will now be able to access the Docker internal DNS

# How does it work
The main problem with the Docker DNS is that it runs inside the network namespace of each container, on a local address (127.0.0.11). Since gVisor containers do not run directly inside that network namespace, they cannot address this service. But [gVisor network traffic is still seen by that netns](https://gvisor.dev/docs/architecture_guide/networking/), meaning we can intercept it.

This project setup rules on each gVisor (runsc) container netns on startup, redirecting UDP traffic to port 53 of the gateway (e.g. 172.22.0.1) to 127.0.0.11, instead of letting it access the host as intended.

It also overrides /etc/resolv.conf inside the container, by changing the DNS from 127.0.0.11 to, e.g., 172.22.0.1. This could theoretically be handlded by routing rules in the namespace

# Limitations
- Probably doesn't handle multiple network/network drivers well. Please open an issue if this happen to you
- Patch isn't applied before container startup, so doing `docker run --network=test --rm --runtime runsc -it nicolaka/netshoot nslookup google.com` won't work, or will at least lead to a race condition
