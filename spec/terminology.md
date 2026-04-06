# Terminology (DEFINITION Blocks)

**DEFINITION 1 (Action Bundle).** A well-formed, immutable specification of a single tool action, including at minimum: target identity, scope tags, tool identifier, parameters, expected side effects, data classification/handling notes, time bounds, and an evidence plan.

**DEFINITION 2 (Grid Cell).** The minimal repeatable unit of governed autonomy consisting of one Orchestrator coordinating three role-separated agents: Planning, Execution, and Governance.

**DEFINITION 3 (Governance Verdict).** A deterministic authorization outcome in Verdicts = {ALLOW, BLOCK, ESCALATE}, produced under a version-pinned policy bundle and recorded in an append-only audit record.

**DEFINITION 4 (Confidence Score).** A bounded scalar used only to select an oversight mode (AUTONOMOUS, HITL, ESCALATE), where thresholds are calibration points tuned to organizational risk tolerance and empirical performance.
