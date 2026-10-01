from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import openstack_client as client

PROJECT = "0123456789abcdef0123456789abcdef"
OTHER_PROJECT = "fedcba9876543210fedcba9876543210"
SERVER = "11111111-1111-1111-1111-111111111111"
IMAGE = "22222222-2222-2222-2222-222222222222"
FLAVOR = "33333333-3333-3333-3333-333333333333"
NETWORK = "44444444-4444-4444-4444-444444444444"
PORT = "55555555-5555-5555-5555-555555555555"
VOLUME = "66666666-6666-6666-6666-666666666666"
FLOATING = "77777777-7777-7777-7777-777777777777"
GROUP = "88888888-8888-8888-8888-888888888888"
STACK = "99999999-9999-9999-9999-999999999999"


class Resource(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None

    def to_dict(self, computed=False):
        return dict(self)


def scope():
    return {
        "cloud": "prod", "region": "RegionOne", "interface": "internal",
        "project_id": PROJECT, "connect_timeout": 10, "read_timeout": 60,
        "compute_api_version": "2", "compute_default_microversion": "2.79",
        "volume_api_version": "3",
    }


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        expected = {
            "identity_current",
            "server_list", "server_get", "server_create", "server_start", "server_stop",
            "server_reboot", "server_rebuild", "server_delete", "server_wait",
            "image_list", "image_get", "image_upload",
            "network_manage", "subnet_manage", "router_manage", "port_manage",
            "security_group_manage", "security_group_rule_manage",
            "floating_ip_allocate", "floating_ip_associate", "floating_ip_release",
            "volume_list", "volume_get", "volume_create", "volume_attach",
            "volume_detach", "volume_delete",
            "object_list", "object_upload", "object_download",
            "stack_validate", "stack_create", "stack_update", "stack_status", "stack_delete",
        }
        self.assertEqual(expected, set(self.actions))
        self.assertEqual(36, len(self.actions))

    def test_all_actions_are_flat_stdin_json_with_explicit_scope(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"openstack.{name}", "runner_type": "python",
                    "runtime_version": '\">=3.10\"', "entry_point": "openstack_action.py",
                    "parameter_delivery": "stdin", "parameter_format": "json",
                    "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {value}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"profile_key: \{[^\n]*default: pack\.openstack\.profile")
                for field in ("cloud", "region", "interface", "project_id"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{[^\n]*required: true")
                for field in ("operation", "data", "scope"):
                    self.assertRegex(text, rf"{field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (password|token|auth_url):")

    def test_destructive_metadata_has_confirmation(self):
        destructive = {
            "server_stop", "server_reboot", "server_rebuild", "server_delete",
            "floating_ip_release", "volume_detach", "volume_delete", "object_upload",
            "stack_update", "stack_delete",
        }
        for name in destructive:
            self.assertRegex(self.actions[name], r"(?m)^  confirm: \{[^\n]*required: true")
        for name in ("network_manage", "subnet_manage", "router_manage", "port_manage", "security_group_manage", "security_group_rule_manage"):
            self.assertIn("confirm:", self.actions[name])

    def test_source_license_and_omission_metadata(self):
        revision = "719b93fe95c091d3e75364af66172b6cae68a370"
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.1"', pack)
        self.assertIn('sdk_baseline: "4.18.0"', pack)
        self.assertIn(revision, source)
        self.assertIn("exactly 710", source)
        self.assertIn("expired key", source)
        self.assertIn("unknown_key", source)
        self.assertIn(revision, notice)
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertNotIn("zaqar", (ROOT / "requirements.txt").read_text(encoding="utf-8").lower())


class ValidationTests(unittest.TestCase):
    def test_openstack_ids_accept_common_formats_and_reject_names(self):
        self.assertEqual(PROJECT, client._uuid(PROJECT, "id"))
        self.assertEqual(SERVER, client._uuid(SERVER.upper(), "id"))
        for value in ("web", "../id", "1" * 31, "g" * 32):
            with self.subTest(value=value), self.assertRaises(client.OpenStackPackError):
                client._uuid(value, "id")

    def test_owner_scope_and_bounded_lists(self):
        with self.assertRaisesRegex(client.OpenStackPackError, "different project"):
            client._assert_owner(Resource(id=SERVER, project_id=OTHER_PROJECT), PROJECT)
        result = client._limited(
            [Resource(id=SERVER), Resource(id=IMAGE), Resource(id=FLAVOR)], 2
        )
        self.assertEqual(2, result["count"])
        self.assertTrue(result["truncated"])
        self.assertEqual(IMAGE, result["next_marker"])

    def test_resource_output_is_allowlisted_and_recursively_redacted(self):
        value = Resource(
            id=SERVER, name="web", password="TOP-SECRET", admin_pass="TOP-SECRET",
            metadata={"harmless": "not returned", "token": "TOP-SECRET"},
            flavor={"id": FLAVOR, "secret_value": "TOP-SECRET"},
            outputs=[{"value": "TOP-SECRET"}],
        )
        text = json.dumps(client._resource_dict(value))
        self.assertIn(SERVER, text)
        self.assertNotIn("TOP-SECRET", text)
        self.assertNotIn("outputs", text)
        self.assertNotIn("metadata", text)

    def test_confirmation_is_exact(self):
        for supplied in (None, "DELETE", f"DELETE:{SERVER} "):
            with self.subTest(supplied=supplied), self.assertRaises(client.OpenStackPackError):
                client._confirm({"confirm": supplied}, f"DELETE:{SERVER}")

    def test_artifact_paths_are_confined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe").mkdir()
            (root / "safe" / "image.qcow2").write_bytes(b"image")
            profile = {"artifact_root": directory}
            path = client._safe_artifact(profile, "safe/image.qcow2", existing=True)
            self.assertEqual(root / "safe" / "image.qcow2", path)
            for value in ("/etc/passwd", "../escape", "safe/../escape", "safe//file"):
                with self.subTest(value=value), self.assertRaises(client.OpenStackPackError):
                    client._safe_artifact(profile, value, existing=False)
            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            try:
                (root / "link").symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(client.OpenStackPackError, "escapes"):
                    client._safe_artifact(profile, "link/file", existing=False)
            finally:
                outside.rmdir()


class ConnectionTests(unittest.TestCase):
    def test_private_clouds_file_inline_ca_no_env_and_scope_match(self):
        captured = {}

        class Region:
            def __init__(self):
                self.config = {}

        class Loader:
            def __init__(self, **kwargs):
                captured["loader"] = kwargs
                path = Path(kwargs["config_files"][0])
                captured["config_path"] = path
                captured["mode"] = path.stat().st_mode & 0o777
                captured["document"] = json.loads(path.read_text(encoding="utf-8"))
                ca_path = Path(captured["document"]["clouds"]["prod"]["cacert"])
                captured["ca_path"] = ca_path
                captured["ca_mode"] = ca_path.stat().st_mode & 0o777

            def get_one_cloud(self, cloud):
                captured["selected"] = cloud
                return Region()

        class Connection:
            current_project_id = PROJECT
            current_user_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

            def __init__(self, **kwargs):
                captured["connection"] = kwargs

            def close(self):
                captured["closed"] = True

        openstack_module = types.ModuleType("openstack")
        openstack_module.__path__ = []
        config_module = types.ModuleType("openstack.config")
        config_module.OpenStackConfig = Loader
        connection_module = types.ModuleType("openstack.connection")
        connection_module.Connection = Connection
        openstack_module.config = config_module
        modules = {
            "openstack": openstack_module,
            "openstack.config": config_module,
            "openstack.connection": connection_module,
        }
        profile = {
            "cloud": "prod",
            "config": {
                "auth_type": "v3applicationcredential",
                "auth": {"auth_url": "https://identity.invalid/v3", "project_id": PROJECT},
                "region_name": "RegionOne", "interface": "internal", "verify": True,
                "cacert_pem": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            },
        }
        params = {"cloud": "prod", "region": "RegionOne", "interface": "internal", "project_id": PROJECT, "connect_timeout": 7, "read_timeout": 29}
        with mock.patch.dict(sys.modules, modules), client._connection(profile, params) as (connection, actual_scope):
            self.assertIsInstance(connection, Connection)
            self.assertEqual(PROJECT, actual_scope["project_id"])
            self.assertTrue(captured["config_path"].exists())
            self.assertTrue(captured["ca_path"].exists())
            region = captured["connection"]["config"]
            self.assertEqual((7, 29), region.config["api_timeout"])
        self.assertFalse(captured["config_path"].exists())
        self.assertFalse(captured["ca_path"].exists())
        self.assertEqual(0o600, captured["mode"])
        self.assertEqual(0o600, captured["ca_mode"])
        self.assertFalse(captured["loader"]["load_envvars"])
        self.assertEqual([], captured["loader"]["secure_files"])
        cloud_config = captured["document"]["clouds"]["prod"]
        self.assertEqual(0, cloud_config["connect_retries"])
        self.assertEqual(0, cloud_config["status_code_retries"])
        self.assertTrue(captured["closed"])

    def test_profile_rejects_wrong_scope_insecure_tls_and_worker_ca_paths(self):
        base = {
            "cloud": "prod",
            "config": {
                "auth": {"auth_url": "https://identity.invalid/v3", "project_id": PROJECT},
                "region_name": "RegionOne", "interface": "internal", "verify": True,
            },
        }
        params = {"cloud": "other", "region": "RegionOne", "interface": "internal", "project_id": PROJECT}
        with self.assertRaisesRegex(client.OpenStackPackError, "cloud"), client._connection(base, params):
            pass
        for change in ({"verify": False}, {"cacert": "/tmp/ca.pem"}):
            profile = json.loads(json.dumps(base))
            profile["config"].update(change)
            params["cloud"] = "prod"
            with self.subTest(change=change), self.assertRaises(client.OpenStackPackError), client._connection(profile, params):
                pass


class ActionTests(unittest.TestCase):
    def test_server_create_uses_ids_once_and_never_resolves_names(self):
        compute = mock.Mock()
        compute.get_flavor.return_value = Resource(id=FLAVOR)
        compute.create_server.return_value = Resource(id=SERVER, project_id=PROJECT, status="BUILD")
        image = mock.Mock()
        image.get_image.return_value = Resource(id=IMAGE)
        network = mock.Mock()
        network.get_network.return_value = Resource(id=NETWORK, project_id=PROJECT)
        conn = types.SimpleNamespace(compute=compute, image=image, network=network)
        result = client._server(conn, "server_create", {
            "name": "web", "image_id": IMAGE, "flavor_id": FLAVOR,
            "network_ids": [NETWORK],
        }, scope())
        self.assertTrue(result["accepted"])
        compute.create_server.assert_called_once_with(
            name="web", image_id=IMAGE, flavor_id=FLAVOR, networks=[{"uuid": NETWORK}]
        )
        image.get_image.assert_called_once_with(IMAGE)
        network.get_network.assert_called_once_with(NETWORK)

    def test_server_destructive_action_checks_owner_and_confirmation(self):
        compute = mock.Mock()
        compute.get_server.return_value = Resource(id=SERVER, project_id=PROJECT, status="ACTIVE")
        conn = types.SimpleNamespace(compute=compute)
        with self.assertRaisesRegex(client.OpenStackPackError, "confirm"):
            client._server(conn, "server_stop", {"server_id": SERVER}, scope())
        compute.stop_server.assert_not_called()
        result = client._server(conn, "server_stop", {"server_id": SERVER, "confirm": f"STOP:{SERVER}"}, scope())
        self.assertTrue(result["accepted"])
        compute.stop_server.assert_called_once()
        compute.get_server.return_value = Resource(id=SERVER, project_id=OTHER_PROJECT)
        with self.assertRaisesRegex(client.OpenStackPackError, "different project"):
            client._server(conn, "server_start", {"server_id": SERVER}, scope())

    def test_server_wait_is_bounded_and_exposes_sdk_failure_status(self):
        compute = mock.Mock()
        server = Resource(id=SERVER, project_id=PROJECT, status="BUILD")
        compute.get_server.return_value = server
        compute.wait_for_server.return_value = Resource(id=SERVER, project_id=PROJECT, status="ACTIVE")
        conn = types.SimpleNamespace(compute=compute)
        result = client._server(conn, "server_wait", {
            "server_id": SERVER, "status": "active", "wait_timeout": 90, "poll_interval": 3,
        }, scope())
        self.assertEqual("ACTIVE", result["status"])
        compute.wait_for_server.assert_called_once_with(server, status="ACTIVE", failures=["ERROR"], interval=3, wait=90)
        with self.assertRaises(client.OpenStackPackError):
            client._server(conn, "server_wait", {"server_id": SERVER, "wait_timeout": 1801}, scope())

    def test_network_crud_uses_project_and_blocks_immutable_update(self):
        network = mock.Mock()
        network.networks.return_value = iter([Resource(id=NETWORK, project_id=PROJECT)])
        network.get_subnet.return_value = Resource(id=NETWORK, project_id=PROJECT)
        conn = types.SimpleNamespace(network=network)
        listed = client._network_manage(conn, "network_manage", {"verb": "list", "max_items": 10}, scope())
        self.assertEqual(1, listed["count"])
        network.networks.assert_called_once_with(project_id=PROJECT)
        with self.assertRaisesRegex(client.OpenStackPackError, "immutable"):
            client._network_manage(conn, "subnet_manage", {
                "verb": "update", "resource_id": NETWORK, "network_id": NETWORK,
            }, scope())
        network.update_subnet.assert_not_called()

    def test_security_rule_validates_both_group_ids(self):
        network = mock.Mock()
        network.get_security_group.side_effect = [
            Resource(id=GROUP, project_id=PROJECT), Resource(id=NETWORK, project_id=PROJECT)
        ]
        network.create_security_group_rule.return_value = Resource(id=SERVER, project_id=PROJECT)
        conn = types.SimpleNamespace(network=network)
        result = client._security(conn, "security_group_rule_manage", {
            "verb": "create", "security_group_id": GROUP, "remote_group_id": NETWORK,
            "direction": "ingress", "ethertype": "IPv4", "protocol": "tcp",
            "port_range_min": 443, "port_range_max": 443,
        }, scope())
        self.assertEqual(SERVER, result["id"])
        self.assertEqual(2, network.get_security_group.call_count)

    def test_floating_association_is_idempotent_and_release_binds_port_confirmation(self):
        network = mock.Mock()
        network.get_ip.return_value = Resource(id=FLOATING, project_id=PROJECT, port_id=PORT, fixed_ip_address="10.0.0.2")
        network.get_port.return_value = Resource(id=PORT, project_id=PROJECT)
        conn = types.SimpleNamespace(network=network)
        result = client._floating(conn, "floating_ip_associate", {
            "floating_ip_id": FLOATING, "port_id": PORT, "fixed_ip_address": "10.0.0.2",
        }, scope())
        self.assertTrue(result["unchanged"])
        network.update_ip.assert_not_called()
        with self.assertRaises(client.OpenStackPackError):
            client._floating(conn, "floating_ip_release", {
                "floating_ip_id": FLOATING, "confirm": f"RELEASE:{FLOATING}",
            }, scope())
        client._floating(conn, "floating_ip_release", {
            "floating_ip_id": FLOATING, "confirm": f"RELEASE:{FLOATING}:{PORT}",
        }, scope())
        network.delete_ip.assert_called_once()

    def test_volume_detach_uses_server_and_volume_ids_without_force(self):
        block = mock.Mock()
        volume = Resource(id=VOLUME, project_id=PROJECT, attachments=[{"server_id": SERVER}])
        block.get_volume.return_value = volume
        compute = mock.Mock()
        server = Resource(id=SERVER, project_id=PROJECT)
        compute.get_server.return_value = server
        compute.get_volume_attachment.return_value = Resource(id=VOLUME)
        conn = types.SimpleNamespace(block_storage=block, compute=compute)
        result = client._volume(conn, "volume_detach", {
            "volume_id": VOLUME, "server_id": SERVER,
            "confirm": f"DETACH:{VOLUME}:{SERVER}",
        }, scope())
        self.assertTrue(result["accepted"])
        compute.get_volume_attachment.assert_called_once_with(server, volume)
        compute.delete_volume_attachment.assert_called_once_with(server, volume, ignore_missing=False)

    def test_object_download_is_atomic_bounded_and_cleans_partial_file(self):
        class ObjectStore:
            def __init__(self, chunks):
                self.chunks = chunks

            def get_object(self, name, container, outfile, resp_chunk_size):
                for chunk in self.chunks:
                    outfile.write(chunk)
                outfile.flush()
                return Resource(name=name, container=container, content_length=sum(map(len, self.chunks)))

        with tempfile.TemporaryDirectory() as directory:
            profile = {"artifact_root": directory, "max_artifact_bytes": 16}
            params = {"container": "artifacts", "object_name": "result.bin", "artifact_path": "result.bin", "max_bytes": 8}
            conn = types.SimpleNamespace(object_store=ObjectStore([b"abc", b"def"]))
            result = client._object_store(conn, "object_download", params, profile)
            self.assertEqual(b"abcdef", Path(directory, "result.bin").read_bytes())
            self.assertEqual(6, result["bytes"])
            Path(directory, "result.bin").unlink()
            conn.object_store = ObjectStore([b"12345", b"67890"])
            with self.assertRaisesRegex(client.OpenStackPackError, "exceeds"):
                client._object_store(conn, "object_download", params, profile)
            self.assertFalse(Path(directory, "result.bin").exists())
            self.assertEqual([], list(Path(directory).glob(".attune-openstack-*")))

    def test_heat_status_omits_outputs_and_update_requires_confirmation(self):
        orchestration = mock.Mock()
        stack = Resource(
            id=STACK, project_id=PROJECT, name="demo", stack_status="CREATE_COMPLETE",
            outputs=[{"output_value": "TOP-SECRET"}], parameters={"password": "TOP-SECRET"},
        )
        orchestration.get_stack.return_value = stack
        conn = types.SimpleNamespace(orchestration=orchestration)
        status = client._stack(conn, "stack_status", {"stack_id": STACK}, scope())
        self.assertNotIn("TOP-SECRET", json.dumps(status))
        orchestration.get_stack.assert_called_with(STACK, resolve_outputs=False)
        with self.assertRaisesRegex(client.OpenStackPackError, "confirm"):
            client._stack(conn, "stack_update", {"stack_id": STACK, "template": {"heat_template_version": "2021-04-16"}}, scope())
        orchestration.update_stack.assert_not_called()

    def test_heat_validation_returns_names_but_not_parameter_defaults(self):
        orchestration = mock.Mock()
        orchestration.validate_template.return_value = Resource(
            Description="demo", Parameters={"admin_password": {"Default": "TOP-SECRET"}, "size": {"Default": 1}}
        )
        conn = types.SimpleNamespace(orchestration=orchestration)
        result = client._stack(conn, "stack_validate", {
            "template": {"heat_template_version": "2021-04-16", "resources": {}},
        }, scope())
        self.assertTrue(result["valid"])
        self.assertEqual(["admin_password", "size"], result["parameter_names"])
        self.assertNotIn("TOP-SECRET", json.dumps(result))


class KeyAndEntryPointTests(unittest.TestCase):
    def test_fetch_key_accepts_json_and_hides_lookup_exception(self):
        parsed = types.SimpleNamespace(data=types.SimpleNamespace(value=json.dumps({"cloud": "prod", "config": {}})))
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(return_value=types.SimpleNamespace(status_code=200, parsed=parsed)))
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual("prod", client._fetch_key("pack.openstack.profile")["cloud"])
            fake_secrets.get_key.sync_detailed.assert_called_once_with(
                "pack.openstack.profile", client=fake_attune.context.client
            )
            fake_secrets.get_key.sync_detailed.side_effect = RuntimeError("TOP-SECRET")
            with self.assertRaises(client.OpenStackPackError) as caught:
                client._fetch_key("pack.openstack.profile")
            self.assertNotIn("TOP-SECRET", str(caught.exception))

    def test_entry_point_never_echoes_input_or_unknown_exception(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("openstack_action_test", ROOT / "actions" / "openstack_action.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cases = [("[]", None), ('{"password":"TOP-SECRET"}', RuntimeError("TOP-SECRET"))]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(module, "execute_action", side_effect=error) if error else mock.patch.object(module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "openstack.server_get"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("TOP-SECRET", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
