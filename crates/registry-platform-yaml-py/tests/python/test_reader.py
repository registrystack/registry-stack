"""Python contract tests for the shared configuration reader binding."""

from __future__ import annotations

import unittest

from bootstrap import ensure_built

ensure_built()

from registry_platform_yaml import ConfigReadError, read_document  # noqa: E402

API_VERSION = "id.registrystack.org/formats/platform/python-connection/v1alpha1"
KIND = "PlatformPythonConnection"


def read(contents: bytes):
    return read_document(
        contents,
        file="connection.json",
        api_version=API_VERSION,
        kind=KIND,
    )


class ReaderTests(unittest.TestCase):
    def test_valid_json_returns_plain_python_values(self):
        document = read(
            b'{"apiVersion":"id.registrystack.org/formats/platform/'
            b'python-connection/v1alpha1","kind":"PlatformPythonConnection",'
            b'"service":"example-service","audience":"service",'
            b'"secretProviders":{"environment":{}},"bindings":[]}'
        )
        self.assertEqual(document["kind"], KIND)
        self.assertEqual(document["service"], "example-service")
        self.assertEqual(document["secretProviders"], {"environment": {}})
        self.assertEqual(document["bindings"], [])

    def test_duplicate_json_key_is_refused_with_both_lines(self):
        contents = (
            b'{\n  "apiVersion":"' + API_VERSION.encode() + b'",\n'
            b'  "kind":"PlatformPythonConnection",\n'
            b'  "service":"first",\n  "service":"second"\n}'
        )
        with self.assertRaises(ConfigReadError) as caught:
            read(contents)
        self.assertIsInstance(caught.exception.diagnostics, tuple)
        diagnostic = caught.exception.diagnostics[0]
        self.assertEqual(diagnostic["code"], "yaml.duplicate-key")
        self.assertEqual(diagnostic["source"]["line"], 5)
        self.assertEqual(diagnostic["related"][0]["line"], 4)

    def test_diagnostics_and_exception_do_not_repeat_scalar_values(self):
        canary = "secret-canary-that-must-not-cross-the-reader"
        contents = (
            b'{"apiVersion":"' + API_VERSION.encode() + b'",'
            b'"kind":"wrong-' + canary.encode() + b'"}'
        )
        with self.assertRaises(ConfigReadError) as caught:
            read(contents)
        self.assertEqual(str(caught.exception), "Configuration document was refused")
        self.assertNotIn(canary, repr(caught.exception.diagnostics))

    def test_diagnostic_flood_is_bounded(self):
        members = b",".join(
            b'"duplicate":"value-' + str(index).encode() + b'"' for index in range(150)
        )
        contents = (
            b'{"apiVersion":"' + API_VERSION.encode() + b'",'
            b'"kind":"PlatformPythonConnection",' + members + b"}"
        )
        with self.assertRaises(ConfigReadError) as caught:
            read(contents)
        self.assertLessEqual(len(caught.exception.diagnostics), 101)
        self.assertEqual(
            caught.exception.diagnostics[-1]["code"], "config.too-many-problems"
        )

    def test_input_and_expected_format_parameters_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "file"):
            read_document(b"{}", file="x" * 4097, api_version=API_VERSION, kind=KIND)
        with self.assertRaisesRegex(ValueError, "api_version"):
            read_document(
                b"{}", file="connection.json", api_version="x" * 257, kind=KIND
            )
        with self.assertRaisesRegex(ValueError, "kind"):
            read_document(
                b"{}", file="connection.json", api_version=API_VERSION, kind="bad\nkind"
            )

    def test_registered_connection_format_refuses_unknown_keys(self):
        contents = (
            b'{"apiVersion":"' + API_VERSION.encode() + b'",'
            b'"kind":"PlatformPythonConnection","service":"example-service",'
            b'"audience":"service","secretProviders":{"environment":{}},'
            b'"bindings":[],"unknown":"value-canary"}'
        )
        with self.assertRaises(ConfigReadError) as caught:
            read(contents)
        self.assertEqual(caught.exception.diagnostics[0]["code"], "config.unknown-key")
        self.assertEqual(caught.exception.diagnostics[0]["path"], "/unknown")
        self.assertNotIn("value-canary", repr(caught.exception.diagnostics))

    def test_registered_connection_format_requires_type_discriminator(self):
        contents = (
            b'{"apiVersion":"' + API_VERSION.encode() + b'",'
            b'"kind":"PlatformPythonConnection","service":"example-service",'
            b'"audience":"service","secretProviders":{"environment":{}},'
            b'"bindings":[{"name":"registry","product":"breg",'
            b'"url":"https://registry.example.test/","default":true,'
            b'"credential":{"kind":"private-key-jwt",'
            b'"tokenEndpoint":"https://identity.example.test/token",'
            b'"clientId":"service-1","clientKeyRef":"secret:env/SERVICE_KEY",'
            b'"resource":"urn:example:breg","scopes":["registry.read"]}}]}'
        )
        with self.assertRaises(ConfigReadError) as caught:
            read(contents)
        self.assertEqual(caught.exception.diagnostics[0]["code"], "config.missing-key")
        self.assertEqual(
            caught.exception.diagnostics[0]["path"], "/bindings/0/credential"
        )


if __name__ == "__main__":
    unittest.main()
