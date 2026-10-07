#!/usr/bin/env python3
"""Static air-gap / open-core scanner for previewd.

Offline, standard library only. Complements scripts/airgap-check.sh (which
inspects the *linked* package graph with `go list`); this scanner inspects
*source, deployment files and specs*, which `go list` cannot see.

Inputs (one or more):
  - a repository directory, or
  - a repomix XML pack (repomix-output.xml), or
  - individual files (specs such as MVP-previewd.md).

Usage:
  airgap_scan.py PATH [PATH...] [--json] [--fail-on high|medium|low|never]

Suppress a deliberate, reviewed exception on its own line with a comment
containing `airgap:allow <reason>`.

Vendored from the airgap-audit skill so the rules are versioned and run in
`make check`. Change the rules here, then update the skill from this file.
AG-09 follows Traefik's static configuration sources: a configuration file
(--configFile, or a file mounted at a default location) replaces CLI flags
and environment variables, so the update check and the usage telemetry must
be disabled in that file's `global` section; without a file, by CLI flags or
TRAEFIK_GLOBAL_* environment variables.

Exit status: 1 when a finding at or above --fail-on exists (default medium).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

SEVERITY = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# --- Rule data ---------------------------------------------------------------

# Never linked into the core: telemetry, exporters, gRPC, cloud SDKs.
# Mirrors scripts/airgap-check.sh so both tools agree.
FORBIDDEN_MODULE = re.compile(
    r"^(go\.opentelemetry\.io/otel/sdk|go\.opentelemetry\.io/otel/exporters/"
    r"|go\.opentelemetry\.io/contrib/exporters/"
    r"|go\.opentelemetry\.io/contrib/(detectors|propagators)/(aws|gcp|azure)"
    r"|go\.opentelemetry\.io/proto/|google\.golang\.org/grpc"
    r"|google\.golang\.org/api/|cloud\.google\.com/go|github\.com/aws/"
    r"|github\.com/Azure/azure-sdk-for-go|github\.com/getsentry/"
    r"|github\.com/DataDog/|github\.com/newrelic/|github\.com/honeycombio/"
    r"|github\.com/segmentio/analytics)"
)

# Enterprise-only per the V1 spec: must not appear in the public core.
ENTERPRISE_MODULE = re.compile(
    r"^(k8s\.io/(client-go|api|apimachinery)|sigs\.k8s\.io/controller-runtime"
    r"|github\.com/hashicorp/vault/api|github\.com/[^/]+/previewd-enterprise)"
)

MANAGED_CLOUD_TEXT = re.compile(
    r"(AWS\s+Secrets\s+Manager|Azure\s+Key\s+Vault|(Google|GCP)\s+Secret\s+Manager"
    r"|AWS\s+KMS|S3\s+bucket|CloudWatch|Datadog|Sentry)",
    re.IGNORECASE,
)

# A sentence that forbids or lists forbidden vendors is not a dependency.
PROHIBITION = re.compile(
    r"\b(fails? on|forbid\w*|never|must not|no circumstances|prohibit\w*|refus\w*|reject\w*|blocked?)\b",
    re.IGNORECASE,
)

PUBLIC_REGISTRIES = {
    "docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io",
    "gcr.io", "k8s.gcr.io", "registry.k8s.io", "mcr.microsoft.com",
    "public.ecr.aws",
}

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
URL = re.compile(r"https?://[^\s\"'`)<>\\]+")
URL_IGNORE_HOST = re.compile(
    r"^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|.*\.localhost|.*\.test|.*\.local"
    r"|.*\.invalid|(.+\.)?example\.(com|org|net)|www\.apache\.org|json-schema\.org"
    r"|www\.w3\.org|schemas\..*|host(name)?|.*[%\[\]{}$<>].*)$"
)
VCS_HOSTS = {"api.github.com", "github.com"}
NETWORK_FETCH = re.compile(
    r"\b(go get|go install|pip3? install|npm (i|install|ci)\b"
    r"|apt(-get)? (install|update)|apk add|yum install|dnf install|docker pull"
    r"|git clone https?://)"
)
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b")

# Local, git-ignored tool directories are skipped so a local scan matches CI.
SKIP_DIRS = {".git", "node_modules", "vendor", "bin", "build", "tmp", ".idea", ".agent", ".agy", ".claude", ".gemini"}
TEXT_EXT = {".go", ".sh", ".yml", ".yaml", ".toml", ".service", ".slice", ".conf",
            ".json", ".md", ".mod", ".txt", ""}


@dataclass
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    message: str


# --- Input handling ----------------------------------------------------------

def iter_repomix(text: str):
    for m in re.finditer(r'<file path="([^"]+)">\n(.*?)\n</file>', text, re.DOTALL):
        yield m.group(1), m.group(2)


def iter_inputs(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    full = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in TEXT_EXT and f not in ("Makefile", "Dockerfile"):
                        continue
                    try:
                        with open(full, encoding="utf-8") as fh:
                            yield os.path.relpath(full, p), fh.read()
                    except (UnicodeDecodeError, OSError):
                        continue
        else:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if p.endswith(".xml") and "<file_summary>" in text[:2000]:
                yield from iter_repomix(text)
            else:
                yield os.path.basename(p), text


# --- Classification ----------------------------------------------------------

def is_test_only(path: str, text: str) -> bool:
    if path.endswith("_test.go") or "/testdata/" in "/" + path:
        return True
    head = "\n".join(text.splitlines()[:5])
    return bool(re.search(r"//go:build\s+.*\be2e\b", head))


def is_comment(line: str, path: str) -> bool:
    s = line.strip()
    if path.endswith(".go"):
        return s.startswith("//") or s.startswith("*") or s.startswith("/*")
    if path.endswith((".md",)):
        return False
    return s.startswith("#")


# --- Rules -------------------------------------------------------------------

def scan_gomod(path, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line:
            continue
        s = line.strip()
        if s.startswith("replace "):
            out.append(Finding("MEDIUM", "AG-01", path, n,
                               "replace directive: release binary must not carry replaced modules"))
        m = re.match(r"^(?:require\s+)?([\w.\-]+/[\w./\-]+)\s+v[\w.\-+]+", s)
        if not m:
            continue
        mod = m.group(1)
        indirect = "// indirect" in s
        if FORBIDDEN_MODULE.match(mod):
            out.append(Finding("MEDIUM" if indirect else "HIGH", "AG-01", path, n,
                               f"forbidden telemetry/cloud module {mod}"
                               + (" (indirect: confirm with `go list -deps`)" if indirect else "")))
        if ENTERPRISE_MODULE.match(mod):
            out.append(Finding("HIGH", "AG-07", path, n,
                               f"enterprise-only module {mod} in the public core (open-core boundary)"))


def scan_go_imports(path, text, out):
    in_import = False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("import ("):
            in_import = True
            continue
        if in_import and s == ")":
            in_import = False
            continue
        m = re.match(r'^(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"$', s) if (in_import or s.startswith("import ")) else None
        if not m or "airgap:allow" in line:
            continue
        imp = m.group(1)
        if FORBIDDEN_MODULE.match(imp):
            out.append(Finding("HIGH", "AG-01", path, n, f"imports forbidden package {imp}"))
        if ENTERPRISE_MODULE.match(imp):
            out.append(Finding("HIGH", "AG-07", path, n,
                               f"imports enterprise-only package {imp} (open-core boundary)"))


def parse_image(ref: str):
    """Return (registry, has_digest, is_mutable)."""
    ref = ref.strip("\"'")
    has_digest = bool(DIGEST.search(ref))
    name = ref.split("@")[0]
    first = name.split("/")[0]
    registry = first if ("/" in name and ("." in first or ":" in first or first == "localhost")) else "docker.io"
    tag = name.rsplit(":", 1)[1] if ":" in name.split("/")[-1] else ""
    mutable = tag in ("", "latest")
    return registry, has_digest, mutable


def check_image(path, n, ref, out, in_deployments):
    if ref.startswith("$") or "${" in ref:
        out.append(Finding("INFO", "AG-02", path, n, f"image {ref} is parameterised: verify the default is digest-pinned"))
        return
    registry, has_digest, mutable = parse_image(ref)
    if mutable:
        out.append(Finding("HIGH", "AG-02", path, n, f"image {ref} uses a mutable tag (:latest or none)"))
    elif not has_digest:
        out.append(Finding("HIGH" if in_deployments else "MEDIUM", "AG-02", path, n,
                           f"image {ref} is not digest-pinned (@sha256:...)"))
    if registry in PUBLIC_REGISTRIES:
        out.append(Finding("INFO", "AG-03", path, n,
                           f"image {ref} resolves to public registry {registry}: the install must load it from a tar or an internal mirror"))


def scan_compose(path, text, out):
    in_dep = path.startswith("deployments/") or "/deployments/" in path
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line or is_comment(line, path):
            continue
        m = re.match(r"^\s*image:\s*(\S+)", line)
        if m:
            check_image(path, n, m.group(1), out, in_dep)
        if "docker.sock" in line:
            out.append(Finding("HIGH", "AG-04", path, n,
                               "Docker socket referenced in a deployment file: root-equivalent; previewd routes via file provider"))
        if re.search(r"providers\.docker", line, re.IGNORECASE):
            out.append(Finding("HIGH", "AG-04", path, n, "Traefik Docker provider enabled (needs the socket and trusts container labels)"))
        if re.search(r"api\.insecure\s*=?\s*true", line, re.IGNORECASE):
            out.append(Finding("HIGH", "AG-04", path, n, "Traefik insecure API/dashboard enabled"))


def scan_dockerfile(path, text, out):
    stages = set()
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line or is_comment(line, path):
            continue
        m = re.match(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if m:
            ref, alias = m.group(1), m.group(2)
            if ref.lower() != "scratch" and ref not in stages:
                check_image(path, n, ref, out, False)
            if alias:
                stages.add(alias)
        if re.match(r"^\s*ADD\s+https?://", line, re.IGNORECASE):
            out.append(Finding("HIGH", "AG-02", path, n, "ADD <url>: the daemon downloads from the host namespace"))


def scan_urls(path, text, out):
    ext = os.path.splitext(path)[1]
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line or is_comment(line, path):
            continue
        for m in URL.finditer(line):
            url = m.group(0).rstrip(".,;")
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            if URL_IGNORE_HOST.match(host):
                continue
            if host in VCS_HOSTS:
                out.append(Finding("INFO", "AG-05", path, n,
                                   f"{host} default endpoint: must be overridable for GHES / on-prem VCS and documented"))
                continue
            if path.endswith("Makefile") and re.match(r"^\s*\w+\s*\?=", line):
                out.append(Finding("INFO", "AG-05", path, n,
                                   f"overridable default {url}: confirm the air-gapped override is documented"))
                continue
            if ext == ".go":
                sev = "MEDIUM"
            elif ext in (".sh", "") or path.endswith("Makefile"):
                sev = "LOW"
            else:
                sev = "MEDIUM"
            out.append(Finding(sev, "AG-05", path, n,
                               f"hard-coded external URL {url}: air-gapped hosts cannot reach it"))


def scan_network_fetch(path, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line or is_comment(line, path):
            continue
        if PIPE_TO_SHELL.search(line):
            out.append(Finding("HIGH", "AG-06", path, n,
                               "downloads and executes remote code (curl|sh): forbidden in any shipped path"))
        m = NETWORK_FETCH.search(line)
        if m:
            out.append(Finding("LOW", "AG-06", path, n,
                               f"install/build-time network fetch `{m.group(1)}`: must run on a connected build host only"))


def scan_systemd(path, text, out):
    if "IPAddressDeny" not in text:
        out.append(Finding("MEDIUM", "AG-08", path, 1,
                           "no IPAddressDeny=: kernel egress backstop missing for this unit"))


def scan_docs(path, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        if "airgap:allow" in line:
            continue
        m = MANAGED_CLOUD_TEXT.search(line)
        if m and not PROHIBITION.search(line):
            out.append(Finding("MEDIUM", "AG-07", path, n,
                               f"spec names managed-cloud service '{m.group(1)}': unusable for air-gapped customers; "
                               "specify an on-prem backend (HashiCorp Vault / OpenBao) behind the interface"))
        if (re.search(r"traefik", line, re.IGNORECASE)
                and re.search(r"docker\s+socket|docker\.sock", line, re.IGNORECASE)
                and not re.search(r"\b(no|not|never|without|neither|nor)\b", line, re.IGNORECASE)):
            out.append(Finding("LOW", "AG-10", path, n,
                               "spec describes socket-based Traefik routing; shipped design is socket-less file provider (doc drift)"))


# --- AG-09: Traefik update check and usage telemetry -------------------------

TRAEFIK_SETTINGS = (
    ("checknewversion", "checknewversion (outbound call to the update service)"),
    ("sendanonymoususage", "sendanonymoususage (usage telemetry)"),
)
TRAEFIK_DEFAULT_FILES = ("/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml", "/etc/traefik/traefik.toml")


def _content_lines(text):
    """(line number, line) for every line that is not blank or a # comment."""
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s and not s.startswith("#"):
            yield n, line


def is_traefik_static_config(path, text):
    """A Traefik static configuration file: top-level entryPoints or providers."""
    if path.endswith(".toml"):
        return bool(re.search(r"^\s*\[(entrypoints|providers)[.\]]", text, re.IGNORECASE | re.MULTILINE))
    if path.endswith((".yml", ".yaml")):
        return any(re.match(r"^(entrypoints|providers)\s*:", line, re.IGNORECASE) for _, line in _content_lines(text))
    return False


def static_disabled(path, text):
    """Settings set to false in the `global` section of a static config file."""
    found = set()
    if path.endswith(".toml"):
        section = None
        for _, line in _content_lines(text):
            m = re.match(r"^\s*\[([^\]]+)\]", line)
            if m:
                section = m.group(1).strip().lower()
                continue
            m = re.match(r"^\s*(\w+)\s*=\s*false\b", line, re.IGNORECASE)
            if m and section == "global":
                found.add(m.group(1).lower())
        return found
    in_global = False
    for _, line in _content_lines(text):
        top = re.match(r"^(\w+)\s*:(.*)$", line)
        if top:
            in_global = top.group(1).lower() == "global"
            if in_global:  # flow style: global: {checkNewVersion: false, ...}
                for m in re.finditer(r"(\w+)\s*:\s*false\b", top.group(2), re.IGNORECASE):
                    found.add(m.group(1).lower())
            continue
        m = re.match(r"^\s+(\w+)\s*:\s*false\b", line, re.IGNORECASE)
        if in_global and m:
            found.add(m.group(1).lower())
    return found


def traefik_services(text):
    """Line blocks of compose services whose image is Traefik."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not re.match(r"^\s*image:\s*[\"']?([\w./-]*/)?traefik[:@\"'\s]", line + " ", re.IGNORECASE):
            continue
        indent = len(line) - len(line.lstrip())
        start = i
        while start > 0:
            prev = lines[start - 1]
            if prev.strip() and len(prev) - len(prev.lstrip()) < indent:
                break
            start -= 1
        end = i + 1
        while end < len(lines):
            nxt = lines[end]
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) < indent:
                break
            end += 1
        yield start + 1, lines[start - 1:end] if start > 0 else lines[:end]


def check_traefik(files, out):
    by_path = {os.path.normpath(p): (p, t) for p, t in files}
    referenced = set()
    for path, text in files:
        if not path.endswith((".yml", ".yaml")) or is_test_only(path, text):
            continue
        for line_no, block in traefik_services(text):
            body = "\n".join(l for l in block if not l.strip().startswith("#"))
            lower = body.lower()
            m = re.search(r"--configfile[= ]\s*[\"']?([^\s\"']+)", lower)
            config_path = m.group(1) if m else None
            mounts = {}
            for vm in re.finditer(r"^\s*-\s*[\"']?([^\s\"':]+):([^\s\"':]+)(?::[a-z,]+)?[\"']?\s*$", body, re.MULTILINE):
                mounts[vm.group(2)] = vm.group(1)
            if config_path is None:
                config_path = next((d for d in TRAEFIK_DEFAULT_FILES if d in mounts), None)
            if config_path is None:
                for key, what in TRAEFIK_SETTINGS:
                    flag = re.search(r"--global\.%s\s*=\s*false\b" % key, lower)
                    env = re.search(r"traefik_global_%s\s*[=:]\s*[\"']?false\b" % key, lower)
                    if not (flag or env):
                        out.append(Finding("HIGH", "AG-09", path, line_no, f"Traefik does not disable {what}"))
                continue
            for key, _ in TRAEFIK_SETTINGS:
                if re.search(r"--global\.%s" % key, lower) or re.search(r"traefik_global_%s" % key, lower):
                    out.append(Finding("LOW", "AG-09", path, line_no,
                                       f"--global.{key} / TRAEFIK_GLOBAL_{key.upper()} is inert: Traefik ignores flags and "
                                       f"environment when a configuration file ({config_path}) is used"))
            source = mounts.get(config_path)
            resolved = None
            if source and not source.startswith(("$", "/")):
                resolved = os.path.normpath(os.path.join(os.path.dirname(path), source))
            if resolved not in by_path:
                out.append(Finding("MEDIUM", "AG-09", path, line_no,
                                   f"Traefik reads {config_path} from {source or 'an unmounted path'}, which this scan "
                                   "cannot see: cannot verify checknewversion and sendanonymoususage are disabled"))
                continue
            referenced.add(resolved)
            cfg_path, cfg_text = by_path[resolved]
            disabled = static_disabled(cfg_path, cfg_text)
            for key, what in TRAEFIK_SETTINGS:
                if key not in disabled:
                    out.append(Finding("HIGH", "AG-09", path, line_no,
                                       f"Traefik configuration file {cfg_path} does not disable {what} in its global section"))
    for path, text in files:
        norm = os.path.normpath(path)
        if norm in referenced or is_test_only(path, text) or not is_traefik_static_config(path, text):
            continue
        disabled = static_disabled(path, text)
        for key, what in TRAEFIK_SETTINGS:
            if key not in disabled:
                out.append(Finding("HIGH", "AG-09", path, 1,
                                   f"Traefik static configuration does not disable {what} in its global section"))


def cross_checks(files, out):
    """Checks needing several files."""
    check_traefik(files, out)
    gomod = next((t for p, t in files if p == "go.mod"), None)
    readme = next((t for p, t in files if p == "README.md"), None)
    if gomod and readme:
        g = re.search(r"^go (\d+\.\d+(?:\.\d+)?)", gomod, re.MULTILINE)
        r = re.search(r"`go\.mod` declares `go (\d+\.\d+(?:\.\d+)?)`", readme)
        if g and r and g.group(1) != r.group(1):
            line_no = readme[:r.start()].count("\n") + 1
            out.append(Finding("LOW", "AG-10", "README.md", line_no,
                               f"README says go.mod declares go {r.group(1)} but go.mod has go {g.group(1)} (doc drift)"))

    has_deny = any(
        p.endswith((".service", ".conf")) and "IPAddressDeny" in t for p, t in files
    )
    if has_deny:
        for p, t in files:
            if p.endswith(".go") and not is_test_only(p, t) and "CgroupVersion" in t:
                for n, line in enumerate(t.splitlines(), 1):
                    if re.match(r'^\s*case\s+"1":', line):
                        out.append(Finding("MEDIUM", "AG-08", p, n,
                                           "cgroup v1 accepted while IPAddressDeny (cgroup v2 only) is the egress backstop: "
                                           "the control is silently inert on v1; refuse v1 at startup"))
                        break


def scan(files):
    out: list[Finding] = []
    for path, text in files:
        base = os.path.basename(path)
        test_only = is_test_only(path, text)
        if base == "go.mod":
            scan_gomod(path, text, out)
        elif path.endswith(".go") and not test_only:
            scan_go_imports(path, text, out)
            scan_urls(path, text, out)
        elif path.endswith((".yml", ".yaml")) and not test_only:
            scan_compose(path, text, out)
            scan_urls(path, text, out)
        elif base.startswith("Dockerfile") or base.endswith(".Dockerfile"):
            scan_dockerfile(path, text, out)
            scan_network_fetch(path, text, out)
        elif path.endswith((".service", ".slice")) or "docker.service.d" in path:
            if path.endswith(".service") or "docker.service.d" in path:
                scan_systemd(path, text, out)
            scan_urls(path, text, out)
        elif path.endswith((".sh",)) or base == "Makefile":
            if not test_only:
                scan_urls(path, text, out)
                scan_network_fetch(path, text, out)
        elif path.endswith((".conf", ".json", ".toml")) and not test_only:
            scan_urls(path, text, out)
        elif path.endswith(".md"):
            scan_docs(path, text, out)
    cross_checks(files, out)
    out.sort(key=lambda f: (-SEVERITY[f.severity], f.path, f.line))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", default="medium", choices=["high", "medium", "low", "never"])
    args = ap.parse_args(argv)

    files = list(iter_inputs(args.paths))
    if not files:
        print("airgap_scan: no readable input files", file=sys.stderr)
        return 2
    findings = scan(files)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"[{f.severity}] {f.rule} {f.path}:{f.line} {f.message}")
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY}
        print(f"\nscanned {len(files)} files: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY))

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY[args.fail_on.upper()]
    return 1 if any(SEVERITY[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
