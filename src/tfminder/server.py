"""MCP server: the only surface an AI agent gets.

Which tools exist depends on ``tier`` in .tfminder.yaml:

    read   list_workspaces, list_requests, get_request, drift_scan
    plan   + review_plan, submit_for_approval
    apply  + apply_approved

There is no approve or reject tool at any tier. Approval is a human action
taken outside the agent's tool surface (``tfminder approve`` in a terminal).
"""

from __future__ import annotations

import os
from typing import Any

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as FastMCP
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError

from .config import Config, ConfigError
from .service import Service, ServiceError
from .store import StoreError
from .worker import JobQueue, WorkerError


def _call(fn: Any, *args: Any) -> Any:
    """Expected failures go back to the agent as a readable tool error, not a crash."""
    try:
        return fn(*args)
    except (ServiceError, ConfigError, StoreError, WorkerError) as exc:
        raise ToolError(str(exc)) from exc

INSTRUCTIONS = """\
tfminder supervises Terraform for you. Workflow:
1. review_plan(workspace, scope=[...]) runs a real plan and returns a request id, the changes, risk findings and a
   decision. Declare in scope exactly the addresses you mean to change; anything else in the plan is flagged.
2. If the decision is 'deny', do not try to work around it: change the code or explain the findings to the user.
3. Otherwise call submit_for_approval(request_id, justification). A human approves it outside this tool.
4. Once get_request shows status 'approved', call apply_approved(request_id) (if your tier allows it).
Never edit files under .tfminder/ and never run terraform apply yourself."""


def agent_actor() -> str:
    return "agent:" + os.environ.get("TFMINDER_AGENT", "mcp")


def build(config: Config, service: Service | None = None) -> FastMCP:
    svc = service or Service(config)
    queue = JobQueue(config.data_dir) if config.executor == "worker" else None

    def execute(op: str, **kwargs: Any) -> Any:
        """Run locally, or hand the job to `tfminder worker` and wait for its result."""
        if queue is None:
            if op == "review":
                return svc.review(actor=agent_actor(), **kwargs)
            if op == "apply":
                return svc.apply(kwargs["request_id"], agent_actor())
            return svc.drift(kwargs["workspace"], agent_actor())
        job = queue.submit(op, kwargs, agent_actor())
        return queue.wait(job, config.worker_wait_seconds)
    mcp = FastMCP("tfminder", instructions=INSTRUCTIONS)

    @mcp.tool()
    def list_workspaces() -> list[dict[str, Any]]:
        """List the Terraform workspaces you may work on, with the policy that governs each one."""
        return svc.workspaces()

    @mcp.tool()
    def list_requests(limit: int = 20) -> list[dict[str, Any]]:
        """Most recent change requests with their status (reviewed, pending, approved, applied, denied...)."""
        return [
            {k: r.to_dict()[k] for k in ("id", "workspace", "status", "decision", "worst_severity", "created_at",
                                         "justification")}
            for r in svc.store.all()[: max(1, min(limit, 100))]
        ]

    @mcp.tool()
    def get_request(request_id: str) -> dict[str, Any]:
        """Full detail of one change request: status, decision, reasons, planned changes and findings."""
        return _call(svc.details, request_id)

    @mcp.tool()
    def drift_scan(workspace: str) -> dict[str, Any]:
        """Compare live Google Cloud resources with Terraform state: resources created by hand (ClickOps),
        resources in state that no longer exist, IaC coverage, and ready-to-use import {} blocks."""
        return _call(lambda: execute("drift", workspace=workspace))

    if config.allows("plan"):
        @mcp.tool()
        def review_plan(
            workspace: str,
            justification: str = "",
            scope: list[str] | None = None,
            destroy: bool = False,
        ) -> dict[str, Any]:
            """Run `terraform plan` in a workspace and review it. Returns a request id, the planned changes,
            risk findings and the policy decision (allow / approval / deny / noop). Nothing is applied.

            scope: the Terraform addresses you intend to change, as glob patterns
            (for example ["google_compute_firewall.iap_ssh", "module.network.*"]). If the plan touches
            anything outside it, the change is flagged (RD007) and, by default, denied. Always declare it."""
            return _call(lambda: execute("review", workspace=workspace, justification=justification,
                                         destroy=destroy, scope=scope))

        @mcp.tool()
        def submit_for_approval(request_id: str, justification: str) -> dict[str, Any]:
            """Ask a human to approve a reviewed plan. Explain in the justification why the change is needed
            and address every finding. Denied plans cannot be submitted."""
            return _call(svc.request_apply, request_id, agent_actor(), justification).to_dict()

    if config.allows("apply"):
        @mcp.tool()
        def apply_approved(request_id: str) -> dict[str, Any]:
            """Apply a plan a human has approved. Applies exactly the reviewed plan file; fails if the approval
            expired, the plan file changed, or state moved since the plan."""
            return _call(lambda: execute("apply", request_id=request_id))

    return mcp


def serve(config: Config) -> None:
    build(config).run()
