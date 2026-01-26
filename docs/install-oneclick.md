# Slipstream One-Click Install (Interactive Script)

This document introduces Slipstream's interactive installation script. It asks a few short
questions, installs the required packages, builds the binaries, and optionally starts the
service for you.

## Prerequisites

- sudo access (for installing dependencies)
- Internet access to install Rust (if missing)
- Run the script from the project repository root

## Quick Run

```bash
./scripts/installer.sh
```

## Choose the Install Mode

When you run the script, you'll be asked which components you want to install:

- **client**: client only
- **server**: server only
- **both**: both

You can also specify the mode directly:

```bash
./scripts/installer.sh --mode client
./scripts/installer.sh --mode server
./scripts/installer.sh --mode both
```

## Running the Service

At the end of the installation you'll be asked whether you'd like to start the service
right away. If you skip running it, the script will print the ready-to-run command.

## Important Notes

- For the server, you must enter the `--cert` and `--key` paths. If these files do not exist,
  the server will automatically generate a self-signed certificate and key at runtime.
- If you are not using a DNS resolver, provide the `authoritative` value.
- For more advanced configuration, see `docs/usage.md`.
