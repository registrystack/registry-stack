import ipaddress
import re
import unittest
from pathlib import Path

POSTGRES = Path(__file__).resolve().parents[1] / "postgres"
# BReg's roles, the identity example's role and a product an adopter adds.
PRODUCT_ROLES = ("registry_runtime", "registry_migration", "registry_identity", "casework_runtime")
PRODUCT_DATABASES = ("registry_breg", "thunderid_config", "thunderid_entity", "registry_casework")
SHARED_DATABASES = ("postgres", "template0", "template1")
ADDRESSES = ("10.42.0.7", "fd00::7")
CONNECTION_TYPES = {"local", "host", "hostssl", "hostnossl"}


def hba_rules():
    """Return the reference pg_hba.conf rules in order, refusing forms this model does not evaluate."""
    lines = (POSTGRES / "postgres.yaml").read_text().splitlines()
    rules = []
    for line in lines[lines.index("  pg_hba.conf: |") + 1:]:
        if not line.startswith("    "):
            break
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        kind = fields[0]
        names = fields[1].split(",") + fields[2].split(",")
        if (
            kind not in CONNECTION_TYPES or len(fields) != (4 if kind == "local" else 5)
            or any(name[:1] in {"@", "/", "+", '"'} or name in {"sameuser", "samerole", "samegroup", "replication"}
                   for name in names)
        ):
            raise ValueError(f"Unmodelled pg_hba rule: {line.strip()}")
        rules.append(fields)
    return rules


def hba_method(connection, database, role, address=None):
    """Return the method of the first rule PostgreSQL matches, or None when no rule matches.

    connection is local, hostssl for a TLS TCP session or hostnossl for a plain one.
    """
    for kind, databases, roles, *rest in hba_rules():
        if kind == "local":
            if connection != "local":
                continue
        elif connection == "local" or kind not in {"host", connection}:
            continue
        elif ipaddress.ip_address(address) not in ipaddress.ip_network(rest[0]):
            continue
        if {"all", database} & set(databases.split(",")) and {"all", role} & set(roles.split(",")):
            return rest[-1]
    return None


def provisioning_sql():
    return (POSTGRES / "provision-breg.sql").read_text()


def database_names(listing):
    return {name.strip() for name in listing.split(",")}


class NetworkRulesTest(unittest.TestCase):
    def test_no_role_opens_a_network_session_on_a_shared_database(self):
        for database in SHARED_DATABASES:
            for role in (*PRODUCT_ROLES, "postgres"):
                for address in ADDRESSES:
                    for connection in ("hostssl", "hostnossl"):
                        with self.subTest(database=database, role=role, address=address, connection=connection):
                            self.assertEqual(hba_method(connection, database, role, address), "reject")

    def test_product_databases_need_tls_and_a_scram_password(self):
        for database in PRODUCT_DATABASES:
            for role in PRODUCT_ROLES:
                for address in ADDRESSES:
                    with self.subTest(database=database, role=role, address=address):
                        self.assertEqual(hba_method("hostssl", database, role, address), "scram-sha-256")
                        self.assertEqual(hba_method("hostnossl", database, role, address), "reject")

    def test_bootstrap_superuser_stays_local_peer_only(self):
        for database in (*SHARED_DATABASES, *PRODUCT_DATABASES):
            with self.subTest(database=database):
                self.assertEqual(hba_method("local", database, "postgres"), "peer")
                for address in ADDRESSES:
                    self.assertEqual(hba_method("hostssl", database, "postgres", address), "reject")
                for role in PRODUCT_ROLES:
                    self.assertEqual(hba_method("local", database, role), "reject")


class DatabasePrivilegesTest(unittest.TestCase):
    def test_public_cannot_connect_to_shared_or_breg_databases(self):
        revoked = set()
        for listing in re.findall(r"^REVOKE ALL ON DATABASE ([a-z0-9_, ]+) FROM PUBLIC;$", provisioning_sql(), re.M):
            revoked |= database_names(listing)
        # template0 refuses every session because its datallowconn is false.
        self.assertLessEqual({"postgres", "template1", "registry_breg"}, revoked)

    def test_only_breg_roles_may_connect_to_the_breg_database(self):
        sql = provisioning_sql()
        grants = re.findall(r"^GRANT CONNECT ON DATABASE ([a-z0-9_, ]+) TO ([a-z0-9_, ]+);$", sql, re.M)
        self.assertEqual(grants, [("registry_breg", "registry_migration, registry_runtime")])
        self.assertNotRegex(sql, r"(?i)\bGRANT\b[^;]*\bTO\s+PUBLIC\b")

    def test_provisioning_can_run_again(self):
        lines = provisioning_sql().splitlines()
        for number, line in enumerate(lines):
            if not re.match(r"(SELECT ')?CREATE\b", line):
                continue
            with self.subTest(line=line):
                guarded = "IF NOT EXISTS" in line or (
                    line.startswith("SELECT 'CREATE ") and lines[number + 1].startswith("WHERE NOT EXISTS ")
                    and lines[number + 1].endswith("\\gexec")
                )
                self.assertTrue(guarded)


if __name__ == "__main__":
    unittest.main()
