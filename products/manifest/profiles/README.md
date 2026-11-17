# Profiles

This directory contains the bundled profile descriptors and metadata fixtures
for Registry Manifest. Each subdirectory holds a `profile.yaml` descriptor and
a `fixtures/` directory with example metadata manifests.

Check every descriptor and fixture from `products/manifest` with
`registry-manifest validate-profiles profiles`. A YAML file here that is neither
a descriptor nor a fixture a descriptor lists is reported as a warning, since no
check reads it.

The `example-*` profiles are non-normative working examples.

| Profile | Status | Purpose |
| --- | --- | --- |
| example-benefits-sync | example | Portable metadata expectations for benefits sync registry descriptors and related metadata publication |
| example-civil-registration | example | Non-normative example metadata expectations for a fictional civil registration application |
| example-multi-dataset | example | Two datasets served by one data service, with one first-class distribution |
| example-person-schema | example | Non-normative example metadata expectations for person concept and JSON Schema publication |
| example-social-benefits | example | Non-normative example metadata expectations for a fictional social benefits application |
