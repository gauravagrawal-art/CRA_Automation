"""Flow 4: advisory remediation, verification and finalization.

Flow 4 is deterministic application logic with no AI agent of its own. It reads
the approved registry, the Flow 2 evidence run and the Flow 3 assessment, and
composes remediation items whose recommendations come verbatim from the
approved ``remediation_seed``. It performs no change to any target and calls no
Infrastructure MCP tool: re-scanning means running Flow 2 and Flow 3 again.
"""
