"""Shared service layer for the CLI and the web UI.

Both front ends call these functions, so a workflow step behaves identically
whichever one invoked it. Nothing here prints: callers render.
"""
