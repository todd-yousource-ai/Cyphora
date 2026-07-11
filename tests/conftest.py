"""Shared pytest fixtures / environment setup."""
import os

# Disable the Prometheus exposition HTTP server during tests so multiple
# orchestrator instances don't contend for a fixed TCP port.
os.environ.setdefault("METRICS_PORT", "0")
