"""Infrastructure MCP — read-only technical evidence collection.

This package is code, not an LLM agent. It implements explicitly registered
tool capabilities, validates every argument, enforces allowlists and output
limits, and redacts secrets before any payload leaves the boundary.

It never interprets CRA/ETSI requirements and never returns a verdict.
See README.md in this package for the full policy.
"""
