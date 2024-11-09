# Tailutils

[![Go](https://github.com/drewwalton19216801/tailutils/actions/workflows/go.yml/badge.svg)](https://github.com/drewwalton19216801/tailutils/actions/workflows/go.yml)

# Introduction

## What is `tailutils`?

`tailutils` is a Go library designed to simplify interactions with Tailscale network interfaces on a machine. It currently provides two primary functions:

- `GetTailscaleIP`: Retrieves the IP address assigned to the Tailscale interface.
- `HasTailscaleIP`: Checks whether the machine has an active Tailscale interface.

These utilities are particularly useful for applications that need to:

- Determine if the machine is connected to a Tailscale VPN.
- Retrieve the Tailscale IP for network communications, logging, or configuration purposes.

## Why use `tailutils`?

Managing network interfaces and parsing IP ranges can be intricate and error-prone. tailutils abstracts these complexities, offering a straightforward API to interact with Tailscale interfaces reliably.

## Limitations

Tailutils currently only supports IPv4 discovery. IPv6 support is planned.

## License

Tailutils is licensed under the MIT License.
