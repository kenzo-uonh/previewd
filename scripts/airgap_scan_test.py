#!/usr/bin/env python3
"""Regression tests for airgap_scan.py (run by `make airgap-scan`).

Standard library only, offline. Focus: AG-09 follows Traefik's actual
static-configuration sources, so a correctly configured file-provider
deployment is clean and every way of leaving the update check or the usage
telemetry on is still reported.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("airgap_scan", os.path.join(_HERE, "airgap_scan.py"))
scanner = importlib.util.module_from_spec(_spec)
sys.modules["airgap_scan"] = scanner
_spec.loader.exec_module(scanner)

STATIC_OK = """\
# Traefik static configuration
global:
  checkNewVersion: false
  sendAnonymousUsage: false
entryPoints:
  web:
    address: "172.30.255.2:80"
providers:
  file:
    directory: /etc/traefik/routes
"""

COMPOSE_WITH_FILE = """\
services:
  traefik:
    image: traefik:v3.7.13@sha256:24841fe2de7304c149343d877d2923b4c8800a38ba015dea9174c23b20e344a0
    command:
      - "--configFile=/etc/traefik/traefik.yml"
    volumes:
      - "./traefik.yml:/etc/traefik/traefik.yml:ro"
      - "${PREVIEWD_ROUTES_DIR:-/var/lib/previewd/routes}:/etc/traefik/routes:ro"
"""

COMPOSE_WITH_FLAGS = """\
services:
  traefik:
    image: traefik:v3.7.13@sha256:24841fe2de7304c149343d877d2923b4c8800a38ba015dea9174c23b20e344a0
    command:
      - "--global.checknewversion=false"
      - "--global.sendanonymoususage=false"
      - "--providers.file.directory=/etc/traefik/routes"
"""


def ag09(files):
    return [f for f in scanner.scan(files) if f.rule == "AG-09"]


def severities(findings):
    return sorted(f.severity for f in findings)


class AG09(unittest.TestCase):
    def test_file_provider_deployment_is_clean(self):
        files = [("deployments/docker-compose.yml", COMPOSE_WITH_FILE), ("deployments/traefik.yml", STATIC_OK)]
        self.assertEqual(ag09(files), [])

    def test_cli_flags_without_config_file_are_clean(self):
        self.assertEqual(ag09([("deployments/docker-compose.yml", COMPOSE_WITH_FLAGS)]), [])

    def test_environment_without_config_file_is_clean(self):
        compose = COMPOSE_WITH_FLAGS.replace(
            '      - "--global.checknewversion=false"\n      - "--global.sendanonymoususage=false"\n', "")
        compose += "    environment:\n      TRAEFIK_GLOBAL_CHECKNEWVERSION: \"false\"\n      TRAEFIK_GLOBAL_SENDANONYMOUSUSAGE: \"false\"\n"
        self.assertEqual(ag09([("deployments/docker-compose.yml", compose)]), [])

    def test_missing_cli_flags_reported(self):
        compose = COMPOSE_WITH_FLAGS.replace('      - "--global.sendanonymoususage=false"\n', "")
        findings = ag09([("deployments/docker-compose.yml", compose)])
        self.assertEqual(severities(findings), ["HIGH"])
        self.assertIn("sendanonymoususage", findings[0].message)

    def test_config_file_missing_a_setting_reported(self):
        static = STATIC_OK.replace("  sendAnonymousUsage: false\n", "")
        files = [("deployments/docker-compose.yml", COMPOSE_WITH_FILE), ("deployments/traefik.yml", static)]
        findings = ag09(files)
        self.assertEqual(severities(findings), ["HIGH"])
        self.assertIn("sendanonymoususage", findings[0].message)
        self.assertEqual(findings[0].path, "deployments/docker-compose.yml")

    def test_setting_true_in_config_file_reported(self):
        static = STATIC_OK.replace("checkNewVersion: false", "checkNewVersion: true")
        files = [("deployments/docker-compose.yml", COMPOSE_WITH_FILE), ("deployments/traefik.yml", static)]
        self.assertEqual(severities(ag09(files)), ["HIGH"])

    def test_setting_outside_global_section_reported(self):
        static = STATIC_OK.replace("global:\n  checkNewVersion: false\n  sendAnonymousUsage: false\n", "") + \
            "log:\n  checkNewVersion: false\n  sendAnonymousUsage: false\n"
        files = [("deployments/docker-compose.yml", COMPOSE_WITH_FILE), ("deployments/traefik.yml", static)]
        self.assertEqual(severities(ag09(files)), ["HIGH", "HIGH"])

    def test_commented_out_setting_reported(self):
        static = STATIC_OK.replace("  checkNewVersion: false", "  # checkNewVersion: false")
        files = [("deployments/docker-compose.yml", COMPOSE_WITH_FILE), ("deployments/traefik.yml", static)]
        self.assertEqual(severities(ag09(files)), ["HIGH"])

    def test_flags_next_to_config_file_are_inert(self):
        # Traefik ignores CLI flags when --configFile is set: the flags do not
        # save a file that leaves the settings on.
        compose = COMPOSE_WITH_FILE.replace(
            '      - "--configFile=/etc/traefik/traefik.yml"\n',
            '      - "--configFile=/etc/traefik/traefik.yml"\n'
            '      - "--global.checknewversion=false"\n      - "--global.sendanonymoususage=false"\n')
        files = [("deployments/docker-compose.yml", compose), ("deployments/traefik.yml", "entryPoints:\n  web: {}\n")]
        self.assertEqual(severities(ag09(files)), ["HIGH", "HIGH", "LOW", "LOW"])

    def test_default_location_mount_is_the_config_file(self):
        compose = COMPOSE_WITH_FILE.replace('    command:\n      - "--configFile=/etc/traefik/traefik.yml"\n', "")
        static = STATIC_OK.replace("  checkNewVersion: false\n", "")
        files = [("deployments/docker-compose.yml", compose), ("deployments/traefik.yml", static)]
        findings = ag09(files)
        self.assertEqual(severities(findings), ["HIGH"])
        self.assertIn("checknewversion", findings[0].message)

    def test_unscanned_config_file_cannot_be_verified(self):
        self.assertEqual(severities(ag09([("deployments/docker-compose.yml", COMPOSE_WITH_FILE)])), ["MEDIUM"])
        absolute = COMPOSE_WITH_FILE.replace('"./traefik.yml:', '"/srv/traefik.yml:')
        files = [("deployments/docker-compose.yml", absolute), ("deployments/traefik.yml", STATIC_OK)]
        self.assertEqual(severities(ag09(files)), ["MEDIUM"])

    def test_standalone_static_config_checked(self):
        bare = "[entryPoints.web]\naddress = \":80\"\n"
        self.assertEqual(severities(ag09([("traefik.toml", bare)])), ["HIGH", "HIGH"])
        toml_ok = "[global]\ncheckNewVersion = false\nsendAnonymousUsage = false\n[entryPoints.web]\naddress = \":80\"\n"
        self.assertEqual(ag09([("traefik.toml", toml_ok)]), [])
        flow = "global: {checkNewVersion: false, sendAnonymousUsage: false}\nproviders:\n  file: {}\n"
        self.assertEqual(ag09([("traefik.yml", flow)]), [])

    def test_files_that_merely_mention_traefik_are_not_traefik_configs(self):
        route = '{"http":{"routers":{"pr-1":{"rule":"Host(`pr-1.local`)","service":"pr-1"}}}}\n'
        ci = "jobs:\n  build:\n    steps:\n      - run: echo traefik is pinned in deployments/\n"
        self.assertEqual(ag09([("routes/pr-1-0a0a0a0a0a.yml", route), (".github/workflows/ci.yml", ci)]), [])

    def test_repository_deployments_are_clean(self):
        root = os.path.dirname(_HERE)
        files = list(scanner.iter_inputs([os.path.join(root, "deployments")]))
        files = [(os.path.join("deployments", p), t) for p, t in files]
        self.assertTrue(any(p.endswith("docker-compose.yml") for p, _ in files))
        self.assertEqual(ag09(files), [])
        # And the same files with one setting removed are not.
        mutated = [(p, t.replace("  sendAnonymousUsage: false\n", "")) for p, t in files]
        self.assertEqual(severities(ag09(mutated)), ["HIGH"])


class OtherRulesUnchanged(unittest.TestCase):
    def test_socket_and_docker_provider_still_reported(self):
        compose = COMPOSE_WITH_FLAGS + '    volumes:\n      - "/var/run/docker.sock:/var/run/docker.sock:ro"\n'
        compose = compose.replace("--providers.file.directory", "--providers.docker=true\n      - --providers.file.directory")
        rules = sorted(f.rule for f in scanner.scan([("deployments/docker-compose.yml", compose)]) if f.severity == "HIGH")
        self.assertEqual(rules, ["AG-04", "AG-04"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
