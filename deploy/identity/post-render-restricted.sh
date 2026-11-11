#!/usr/bin/env bash
set -euo pipefail

# ThunderID chart 1.0.1 renders `drop: [all]`. Kubernetes Restricted Pod
# Security requires the canonical capability name `ALL`. Change that scalar
# only, preserving the exact upstream workload otherwise.
yq eval '
  (
    select(.kind == "Deployment" or .kind == "Job")
    | .spec.template.spec.containers[].securityContext.capabilities.drop[]
    | select(. == "all")
  ) = "ALL"
' -
