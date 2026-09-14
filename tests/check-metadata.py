#!/usr/bin/env python3
"""Static checks for action.yml, tools.json and the documentation.

These are the mistakes that unit tests cannot catch and that only show up when
a consumer runs the Action: an input that is never passed to a script, an
output wired to a step that no longer exists, a scanner version bumped without
its checksum, a documented input that does not exist.

Requires only PyYAML, which is pre-installed on GitHub-hosted runners.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
problems: list[str] = []


def check(condition: object, message: str) -> None:
    if not condition:
        problems.append(message)


def load_yaml(relative: str) -> dict:
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# action.yml
# ---------------------------------------------------------------------------
action = load_yaml("action.yml")

check(action.get("name") == "Web Security", f"unexpected action name: {action.get('name')}")
check(action.get("description", "").strip(), "action.yml needs a description")
check(action.get("runs", {}).get("using") == "composite", "the Action must be composite")

branding = action.get("branding") or {}
check(branding.get("icon"), "branding.icon is required for the Marketplace")
check(branding.get("color"), "branding.color is required for the Marketplace")

inputs = action.get("inputs") or {}
outputs = action.get("outputs") or {}
steps = action["runs"]["steps"]

readme = (ROOT / "README.md").read_text(encoding="utf-8")
action_text = (ROOT / "action.yml").read_text(encoding="utf-8")

for name, spec in inputs.items():
    check(spec.get("description", "").strip(), f"input {name} has no description")
    check(f"`{name}`" in readme, f"input {name} is not documented in README.md")
    # Inputs reach the scripts as environment variables. An input that is
    # declared but never mapped is dead API surface.
    env_name = "WEB_SECURITY_INPUT_" + name.replace("-", "_").upper()
    check(env_name in action_text, f"input {name} is never mapped to {env_name}")

for name, spec in outputs.items():
    check(spec.get("description", "").strip(), f"output {name} has no description")
    check(
        "steps.report.outputs." in str(spec.get("value", "")),
        f"output {name} is not wired to the report step",
    )
    check(f"`{name}`" in readme, f"output {name} is not documented in README.md")

step_ids = {step.get("id") for step in steps if step.get("id")}
check("report" in step_ids, "action.yml has no step with id 'report'")

for step in steps:
    run = step.get("run") or ""
    if run:
        check(step.get("shell") == "bash", f"step '{step.get('name')}' must declare shell: bash")
    # Repository content is untrusted, so no step may interpolate an
    # expression into shell text.
    check(
        "${{" not in run,
        f"step '{step.get('name')}' interpolates an expression into a run block",
    )
    check(
        "continue-on-error" not in step,
        f"step '{step.get('name')}' uses continue-on-error; failures must be recorded explicitly",
    )
    check(
        not step.get("uses"),
        f"step '{step.get('name')}' uses a third-party Action; this Action deliberately uses none",
    )
    for script in re.findall(r"\$GITHUB_ACTION_PATH/([\w./-]+\.(?:sh|mjs))", run):
        path = ROOT / script
        check(path.is_file(), f"{script} is referenced by action.yml but does not exist")
        if path.is_file() and script.endswith(".sh"):
            check(os.access(path, os.X_OK), f"{script} is not executable (chmod +x)")

# ---------------------------------------------------------------------------
# tools.json
# ---------------------------------------------------------------------------
tools = json.loads((ROOT / "tools.json").read_text(encoding="utf-8"))
expected_tools = {"trivy", "gitleaks", "semgrep"}
declared = {name for name in tools if not name.startswith("$")}
check(declared == expected_tools, f"tools.json declares {declared}, expected {expected_tools}")

for name in sorted(declared):
    spec = tools[name]
    version = str(spec.get("version", ""))
    check(
        re.fullmatch(r"\d+\.\d+\.\d+", version),
        f"{name} version '{version}' is not pinned to an exact release",
    )
    check(spec.get("binary"), f"{name} has no binary name")
    check(f"`{version}`" in readme, f"{name} {version} is not documented in README.md")

    if spec.get("installer") == "pypi":
        # Installed from PyPI, so there is no archive to checksum; the exact
        # version pin plus wheels-only installation is the control.
        check(
            spec.get("package") == f"{name}=={version}",
            f"{name} package pin '{spec.get('package')}' does not match version {version}",
        )
        continue

    template = str(spec.get("urlTemplate", ""))
    check(template.startswith("https://"), f"{name} is not downloaded over HTTPS")
    check("{version}" in template and "{file}" in template, f"{name} urlTemplate is malformed")
    check(
        version in str(spec.get("checksumsUrl", "")),
        f"{name} checksumsUrl does not reference version {version}",
    )

    assets = spec.get("assets") or {}
    check("linux-x64" in assets, f"{name} has no linux-x64 asset (GitHub-hosted runners need it)")
    for platform, asset in assets.items():
        check(
            version in str(asset.get("file", "")),
            f"{name}/{platform} file '{asset.get('file')}' does not reference version {version}",
        )
        check(
            re.fullmatch(r"[0-9a-f]{64}", str(asset.get("sha256", ""))),
            f"{name}/{platform} has no valid SHA-256 checksum",
        )

# ---------------------------------------------------------------------------
# Schemas, examples and workflows
# ---------------------------------------------------------------------------
json.loads((ROOT / "schemas/web-security-ignore.schema.json").read_text(encoding="utf-8"))
json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

for example in sorted((ROOT / "examples").glob("*.yml")):
    document = yaml.safe_load(example.read_text(encoding="utf-8"))
    check(isinstance(document, dict), f"{example.name} is not a YAML mapping")
    if "ignore" in example.name:
        check("ignores" in document, f"{example.name} has no ignores list")
        check(document.get("version") == 1, f"{example.name} has no version: 1")
        for index, entry in enumerate(document["ignores"]):
            for field in ("id", "scanner", "reason"):
                check(entry.get(field), f"{example.name} ignores[{index}] is missing {field}")
            check(
                len(str(entry.get("reason", ""))) >= 15,
                f"{example.name} ignores[{index}] has a reason the validator would reject",
            )
    else:
        check("jobs" in document, f"{example.name} is not a workflow")
        check(
            document.get("permissions") == {"contents": "read"},
            f"{example.name} should demonstrate least-privilege permissions",
        )

# Every third-party Action in this repository's own workflows must be pinned to
# a full commit SHA, which is what the README asks of consumers.
for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
    text = workflow.read_text(encoding="utf-8")
    for reference in re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, re.MULTILINE):
        if reference.startswith("./"):
            continue
        check(
            re.search(r"@[0-9a-f]{40}$", reference),
            f"{workflow.name} uses {reference}, which is not pinned to a commit SHA",
        )

# The README's minimal example must stay copy-pasteable.
check(
    "uses: keldynai/web-security@v1" in readme,
    "README.md no longer contains the minimal usage example",
)

if problems:
    for problem in problems:
        print(f"::error::{problem}")
    sys.exit(1)

print(f"metadata OK: {len(inputs)} inputs, {len(outputs)} outputs, {len(declared)} pinned tools")
