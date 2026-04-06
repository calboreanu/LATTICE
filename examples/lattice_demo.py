from __future__ import annotations
import argparse
import json
import os
from lattice.execution_gate import enforce
from lattice.sandbox_stub import sandbox_execute

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--policy", required=True, help="Path to policy bundle JSON")
    p.add_argument("--bundle", required=True, help="Path to action bundle JSON")
    p.add_argument("--audit-dir", default=".audit", help="Directory for audit logs")
    args = p.parse_args()

    with open(args.policy, "r", encoding="utf-8") as f:
        policy = json.load(f)
    with open(args.bundle, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    os.makedirs(args.audit_dir, exist_ok=True)
    audit_path = os.path.join(args.audit_dir, "audit_log.jsonl")

    decision, audit_record = enforce(bundle, policy, audit_path)
    print(f"DECISION: {decision}")
    print("AUDIT_RECORD:", json.dumps(audit_record, indent=2))

    if decision == "ALLOW":
        result = sandbox_execute(bundle)
        print("EXECUTION_RESULT:", json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
