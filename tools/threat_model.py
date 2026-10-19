#!/usr/bin/env python3
"""Generate a STRIDE threat model from a component list."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STRIDE = {
    "spoofing": ("S", "Can an actor pretend to be another user or service?"),
    "tampering": ("T", "Can data be modified in transit or at rest?"),
    "repudiation": ("R", "Can an action be denied because it is not logged?"),
    "information-disclosure": ("I", "Can data be read by someone not entitled to it?"),
    "denial-of-service": ("D", "Can a shared resource be exhausted?"),
    "elevation-of-privilege": ("E", "Can a low-privilege actor gain more rights?"),
}

TYPE_THREATS = {
    "web": ["spoofing", "tampering", "information-disclosure", "denial-of-service"],
    "api": ["spoofing", "tampering", "elevation-of-privilege", "denial-of-service"],
    "db": ["tampering", "information-disclosure", "repudiation"],
    "actor": ["spoofing", "repudiation"],
    "process": ["tampering", "denial-of-service", "elevation-of-privilege"],
}

MITIGATIONS = {
    "spoofing": "Strong authentication, MFA for privileged actions, short-lived tokens.",
    "tampering": "Sign or encrypt data, validate input server-side, restrict write access.",
    "repudiation": "Append-only audit log of security-relevant actions with actor identity.",
    "information-disclosure": "Authorization checks per object, least privilege, encryption at rest.",
    "denial-of-service": "Rate limits, quotas, timeouts and backpressure.",
    "elevation-of-privilege": "Deny-by-default authorization, periodic privilege review.",
}


def parse_components(values):
    components = []
    for value in values:
        if ":" not in value:
            raise ValueError(f"component must look like 'Name:type': {value!r}")
        name, kind = value.rsplit(":", 1)
        kind = kind.strip().lower()
        if kind not in TYPE_THREATS:
            raise ValueError(f"unknown component type {kind!r}; use {sorted(TYPE_THREATS)}")
        components.append({"name": name.strip(), "type": kind})
    return components


def build(components, likelihood: int = 3, impact: int = 3):
    model = []
    for component in components:
        threats = []
        for key in TYPE_THREATS[component["type"]]:
            letter, question = STRIDE[key]
            threats.append({
                "stride": letter,
                "category": key,
                "question": question,
                "mitigation": MITIGATIONS[key],
                "likelihood": likelihood,
                "impact": impact,
                "risk": likelihood * impact,
            })
        threats.sort(key=lambda t: t["risk"], reverse=True)
        model.append({**component, "threats": threats})
    return model


def render(model) -> str:
    lines = ["# Threat model", "", "Risk = likelihood x impact (1-5 each).", ""]
    for component in model:
        lines.append(f"## {component['name']} ({component['type']})")
        lines.append("")
        lines.append("| STRIDE | Threat question | Mitigation | Risk |")
        lines.append("|---|---|---|---|")
        for threat in component["threats"]:
            lines.append(f"| {threat['stride']} | {threat['question']} "
                         f"| {threat['mitigation']} | {threat['risk']} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate a STRIDE threat model")
    parser.add_argument("--component", action="append", required=True,
                        help="Name:type (web, api, db, actor, process)")
    parser.add_argument("--likelihood", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--impact", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    try:
        components = parse_components(args.component)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    model = build(components, args.likelihood, args.impact)
    output = json.dumps(model, indent=2) if args.json else render(model)
    if args.out:
        args.out.write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
