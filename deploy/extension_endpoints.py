"""Bind a published workspace endpoint to an operator-owned Helm deployment."""

import copy
import ipaddress
import re

NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
IMAGE = re.compile(r"[a-z0-9]+(?:[.:-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}")
ROUTE = re.compile(r"/extensions/[a-z0-9-]+(?:/[a-z0-9-]+)*")


class EndpointError(Exception):
    """An invalid endpoint declaration or deployment binding."""


def dns_label(value, description):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise EndpointError(f"{description} must be a DNS label.")
    return value


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or "." not in value:
        raise EndpointError("An extension public hostname is required.")
    for label in value.split("."):
        dns_label(label, "Each hostname label")


def labels(value):
    return isinstance(value, dict) and bool(value) and all(
        isinstance(label, str) and label and isinstance(text, str) for label, text in value.items()
    )


def selected_peer(peer):
    if not isinstance(peer, dict) or not peer:
        return False
    if set(peer) == {"ipBlock"}:
        block = peer["ipBlock"]
        return (
            isinstance(block, dict) and set(block) == {"cidr"}
            and isinstance(block["cidr"], str) and ipaddress.ip_network(block["cidr"]).prefixlen > 0
        )
    return peer.keys() <= {"namespaceSelector", "podSelector"} and all(
        isinstance(selector, dict) and set(selector) == {"matchLabels"} and labels(selector["matchLabels"])
        for selector in peer.values()
    )


def egress_rules(rules):
    if not isinstance(rules, list):
        raise EndpointError("Endpoint egress must be a list of selected peers and ports.")
    for rule in rules:
        if (
            not isinstance(rule, dict) or set(rule) != {"to", "ports"} or not selected_peer(rule["to"])
            or not isinstance(rule["ports"], list) or not rule["ports"]
        ):
            raise EndpointError("Each explicit egress rule requires a selected peer and numeric ports.")
        for port in rule["ports"]:
            if (
                not isinstance(port, dict) or port.keys() - {"port", "protocol"}
                or type(port.get("port")) is not int or not 1 <= port["port"] <= 65535
                or port.get("protocol", "TCP") not in {"TCP", "UDP", "SCTP"}
            ):
                raise EndpointError("Endpoint egress needs an exact transport protocol and numeric port.")
    return rules


def bind_endpoint(path, binding):
    allowed = {"image", "port", "imagePullPolicy", "configMapName", "credentialsSecretName", "egress", "hostAliases"}
    if not isinstance(binding, dict) or binding.keys() - allowed:
        raise EndpointError("Unknown or missing operator fields for an endpoint.")
    image, port = binding.get("image"), binding.get("port")
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise EndpointError("Supply a digest-pinned endpoint OCI image.")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise EndpointError("Supply an unprivileged endpoint container port.")
    for key in ("configMapName", "credentialsSecretName"):
        if key in binding:
            dns_label(binding[key], key)
    pull_policy = binding.get("imagePullPolicy", "IfNotPresent")
    if pull_policy not in {"Always", "IfNotPresent", "Never"}:
        raise EndpointError("Invalid endpoint image pull policy.")
    aliases = binding.get("hostAliases", [])
    if not isinstance(aliases, list):
        raise EndpointError("Endpoint host aliases must be a list.")
    for alias in aliases:
        if set(alias) != {"ip", "hostnames"} or not isinstance(alias["hostnames"], list) or not alias["hostnames"]:
            raise EndpointError("Each host alias needs an IP address and hostnames.")
        ipaddress.ip_address(alias["ip"])
        for host in alias["hostnames"]:
            hostname(host)
    return {
        **copy.deepcopy(binding), "path": path, "imagePullPolicy": pull_policy,
        "egress": copy.deepcopy(egress_rules(binding.get("egress", []))),
    }


def extension_values(intent, bindings):
    extensions = intent.get("extensions") if isinstance(intent, dict) and set(intent) == {"extensions"} else None
    if (
        not isinstance(extensions, dict) or set(extensions) != {"endpoints"}
        or not isinstance(extensions["endpoints"], dict) or not extensions["endpoints"]
    ):
        raise EndpointError("The published Helm fragment must contain extensions.endpoints.")
    required = {
        "namespace", "publicHost", "ingressClassName", "ingressNamespace", "ingressPodLabels",
        "tlsSecretName", "endpoints",
    }
    if (
        not isinstance(bindings, dict)
        or not required <= bindings.keys() <= required | {"ingressAnnotations", "imagePullSecrets"}
        or not isinstance(bindings["endpoints"], dict)
    ):
        raise EndpointError("Supply the named Kubernetes and endpoint bindings.")
    for key in ("namespace", "ingressClassName", "ingressNamespace", "tlsSecretName"):
        dns_label(bindings[key], key)
    hostname(bindings["publicHost"])
    if not labels(bindings["ingressPodLabels"]):
        raise EndpointError("Select the ingress controller Pods explicitly.")
    if "ingressAnnotations" in bindings and not labels(bindings["ingressAnnotations"]):
        raise EndpointError("Ingress annotations must map names to text.")
    pull_secrets = bindings.get("imagePullSecrets", [])
    if not isinstance(pull_secrets, list):
        raise EndpointError("Specify image pull Secrets by name in the extension namespace.")
    for secret in pull_secrets:
        if not isinstance(secret, dict) or set(secret) != {"name"}:
            raise EndpointError("Specify image pull Secrets by name in the extension namespace.")
        dns_label(secret["name"], "Image pull Secret")

    endpoints = {}
    routes = set()
    for endpoint, item in extensions["endpoints"].items():
        if not isinstance(item, dict) or set(item) != {"path"}:
            raise EndpointError("A workspace endpoint declares only the path under its endpoint ID.")
        dns_label(endpoint, "Endpoint ID")
        path = item["path"]
        if not isinstance(path, str) or len(path) > 255 or not ROUTE.fullmatch(path) or path in routes:
            raise EndpointError("Each extension route must be distinct and under /extensions/.")
        if endpoint not in bindings["endpoints"] or len(endpoint) > 53:
            raise EndpointError(f"Provide one binding for extension ID {endpoint} (up to 53 characters).")
        routes.add(path)
        endpoints[endpoint] = bind_endpoint(path, bindings["endpoints"][endpoint])
    if endpoints.keys() != bindings["endpoints"].keys():
        raise EndpointError("Operator endpoint bindings must match the published IDs.")
    return {**copy.deepcopy(bindings), "endpoints": endpoints}
