"""Curated, scoped OpenStack SDK actions for Attune."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_PROFILE_KEY = "openstack.profile"
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TEMPLATE_BYTES = 1024 * 1024
MAX_HEAT_RESOURCES = 100
RESOURCE_ID = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
SENSITIVE_KEY = re.compile(r"password|passcode|token|secret|credential|private[_-]?key|admin[_-]?pass", re.IGNORECASE)

PUBLIC_FIELDS = {
    "id", "name", "status", "description", "project_id", "tenant_id", "user_id",
    "created_at", "updated_at", "created", "updated", "region", "size", "visibility",
    "disk_format", "container_format", "checksum", "os_hash_algo", "os_hash_value",
    "min_disk", "min_ram", "protected", "tags", "addresses", "flavor", "image",
    "networks", "attached_volumes", "volumes_attached", "task_state", "power_state",
    "vm_state", "access_ipv4", "access_ipv6", "key_name", "network_id", "cidr",
    "ip_version", "gateway_ip", "enable_dhcp", "dns_nameservers", "allocation_pools",
    "host_routes", "subnet_id", "router_id", "device_id", "device_owner", "mac_address",
    "fixed_ips", "security_group_ids", "port_security_enabled", "admin_state_up",
    "is_admin_state_up", "is_router_external", "external_gateway_info", "mtu",
    "revision_number", "direction", "ethertype", "protocol", "port_range_min",
    "port_range_max", "remote_ip_prefix", "remote_group_id", "security_group_id",
    "floating_ip_address", "fixed_ip_address", "floating_network_id", "port_id",
    "volume_id", "server_id", "attachment_id", "attachments", "availability_zone",
    "volume_type", "bootable", "encrypted", "container", "content_type", "content_length",
    "bytes", "hash", "last_modified", "stack_status", "action",
    "creation_time", "updated_time", "timeout_mins", "capabilities", "count", "truncated",
    "next_marker", "accepted", "unchanged", "path", "sha256",
}


class OpenStackPackError(Exception):
    """An action-safe error that never contains credentials or response bodies."""


def _fetch_key(key_ref: str) -> dict[str, Any]:
    _string(key_ref, "profile_key")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    # Attune client exceptions are not stable across releases; redact all of them.
    except Exception as exc:  # noqa: BLE001
        raise OpenStackPackError(f"could not read OpenStack profile Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise OpenStackPackError("OpenStack profile Key was not found")
        raise OpenStackPackError(f"could not read OpenStack profile Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise OpenStackPackError("OpenStack profile Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise OpenStackPackError("OpenStack profile Key must contain an object")
    return value


def _string(value: Any, name: str, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise OpenStackPackError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 32 for character in value):
        raise OpenStackPackError(f"{name} contains a control character")
    return value


def _uuid(value: Any, name: str) -> str:
    value = _string(value, name, 36)
    if not RESOURCE_ID.fullmatch(value):
        raise OpenStackPackError(f"{name} must be a 32-hex or UUID-formatted OpenStack ID")
    return value.lower()


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise OpenStackPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise OpenStackPackError(f"{name} must be a boolean")
    return value


def _string_list(value: Any, name: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise OpenStackPackError(f"{name} must be an array with at most {maximum} entries")
    return [_string(item, name) for item in value]


def _uuid_list(value: Any, name: str, maximum: int) -> list[str]:
    return [_uuid(item, name) for item in _string_list(value, name, maximum)]


def _dict(value: Any, name: str, maximum: int = 64) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > maximum:
        raise OpenStackPackError(f"{name} must be an object with at most {maximum} fields")
    return value


def _resource_dict(resource: Any) -> dict[str, Any]:
    if resource is None:
        return {}
    if isinstance(resource, dict):
        raw = resource
    elif hasattr(resource, "to_dict"):
        raw = resource.to_dict(computed=False)
    else:
        try:
            raw = dict(resource)
        except (TypeError, ValueError):
            raw = {key: getattr(resource, key) for key in PUBLIC_FIELDS if hasattr(resource, key)}
    return _sanitize({key: value for key, value in raw.items() if key in PUBLIC_FIELDS})


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item)
            for key, item in value.items()
            if not SENSITIVE_KEY.search(str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _owner(resource: Any) -> str | None:
    keys = ("project_id", "tenant_id", "os-vol-tenant-attr:tenant_id")
    if isinstance(resource, dict):
        for key in keys:
            if isinstance(resource.get(key), str):
                return resource[key]
    for key in keys:
        value = getattr(resource, key, None)
        if isinstance(value, str):
            return value
    return None


def _assert_owner(resource: Any, project_id: str) -> None:
    owner = _owner(resource)
    if owner is not None and owner.lower() != project_id:
        raise OpenStackPackError("resource belongs to a different project")


def _confirm(params: dict[str, Any], expected: str) -> None:
    if params.get("confirm") != expected:
        raise OpenStackPackError(f"confirm must equal '{expected}'")


def _limited(resources: Any, maximum: int, project_id: str | None = None) -> dict[str, Any]:
    values = list(islice(iter(resources), maximum + 1))
    truncated = len(values) > maximum
    values = values[:maximum]
    if project_id:
        for value in values:
            _assert_owner(value, project_id)
    items = [_resource_dict(value) for value in values]
    marker = (items[-1].get("id") or items[-1].get("name")) if truncated and items else None
    return {"items": items, "count": len(items), "truncated": truncated, "next_marker": marker}


def _safe_artifact(profile: dict[str, Any], relative: Any, *, existing: bool) -> Path:
    root_value = profile.get("artifact_root")
    if not isinstance(root_value, str) or not os.path.isabs(root_value):
        raise OpenStackPackError("profile artifact_root must be an absolute directory")
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir():
        raise OpenStackPackError("profile artifact_root must be a directory")
    path_value = _string(relative, "artifact_path", 1024)
    if "//" in path_value or "\\" in path_value:
        raise OpenStackPackError("artifact_path must use canonical forward-slash separators")
    candidate_input = Path(path_value)
    if candidate_input.is_absolute() or any(part in {"", ".", ".."} for part in candidate_input.parts):
        raise OpenStackPackError("artifact_path must be a safe relative path")
    if existing:
        candidate = (root / candidate_input).resolve(strict=True)
        if not candidate.is_file():
            raise OpenStackPackError("artifact_path must identify a regular file")
    else:
        parent = (root / candidate_input.parent).resolve(strict=True)
        candidate = parent / candidate_input.name
    try:
        candidate.relative_to(root)
    except ValueError:
        raise OpenStackPackError("artifact_path escapes profile artifact_root") from None
    return candidate


def _artifact_limit(profile: dict[str, Any], params: dict[str, Any]) -> int:
    profile_limit = profile.get("max_artifact_bytes", 10 * 1024**3)
    if isinstance(profile_limit, bool) or not isinstance(profile_limit, int) or not 1 <= profile_limit <= 100 * 1024**3:
        raise OpenStackPackError("profile max_artifact_bytes must be from 1 byte to 100 GiB")
    requested = _integer(params, "max_bytes", profile_limit, 1, profile_limit)
    return requested


def _write_pem(directory: Path, name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("-----BEGIN ") or len(value) > 1024 * 1024:
        raise OpenStackPackError(f"profile {name}_pem must be PEM text of at most 1 MiB")
    path = directory / f"{name}.pem"
    path.write_text(value, encoding="utf-8")
    os.chmod(path, 0o600)
    return str(path)


@contextmanager
def _connection(profile: dict[str, Any], params: dict[str, Any]) -> Iterator[tuple[Any, dict[str, Any]]]:
    try:
        profile_size = len(json.dumps(profile, separators=(",", ":")).encode())
    except (TypeError, ValueError):
        raise OpenStackPackError("OpenStack profile Key must contain JSON-compatible values") from None
    if profile_size > 2 * 1024 * 1024:
        raise OpenStackPackError("OpenStack profile Key exceeds the 2 MiB limit")
    if set(profile) - {"cloud", "config", "artifact_root", "max_artifact_bytes"}:
        raise OpenStackPackError("OpenStack profile Key contains unsupported top-level fields")
    cloud = _string(profile.get("cloud"), "profile cloud")
    if _string(params.get("cloud"), "cloud") != cloud:
        raise OpenStackPackError("requested cloud does not match the profile cloud")
    config = dict(_dict(profile.get("config"), "profile config", 128))
    region = _string(params.get("region"), "region")
    interface = _string(params.get("interface"), "interface", 16)
    project_id = _uuid(params.get("project_id"), "project_id")
    if config.get("region_name") != region:
        raise OpenStackPackError("requested region does not match profile region_name")
    if config.get("interface") != interface or interface not in {"public", "internal", "admin"}:
        raise OpenStackPackError("requested interface does not match a valid profile interface")
    if config.get("verify", True) is not True or config.get("insecure"):
        raise OpenStackPackError("profile must enable TLS certificate verification")
    auth = _dict(config.get("auth"), "profile config.auth", 64)
    auth_url = _string(auth.get("auth_url"), "profile auth_url", 2048)
    parsed_url = urlsplit(auth_url)
    if (parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username
            or parsed_url.password or parsed_url.query or parsed_url.fragment):
        raise OpenStackPackError("profile auth_url must be an HTTPS URL without embedded credentials")
    if not (auth.get("project_id") or auth.get("project_name")):
        raise OpenStackPackError("profile auth must select a project scope")
    if any(key in config for key in ("cacert", "cert", "key")):
        raise OpenStackPackError("profile must use inline cacert_pem/cert_pem/key_pem, not worker paths")

    connect_timeout = _integer(params, "connect_timeout", 10, 1, 30)
    read_timeout = _integer(params, "read_timeout", 60, 1, 300)
    connection = None
    with tempfile.TemporaryDirectory(prefix="attune-openstack-") as temp_name:
        directory = Path(temp_name)
        os.chmod(directory, 0o700)
        for pem_name, config_name in (("cacert", "cacert"), ("cert", "cert"), ("key", "key")):
            inline_name = f"{pem_name}_pem"
            if inline_name in config:
                config[config_name] = _write_pem(directory, pem_name, config.pop(inline_name))
        if bool(config.get("cert")) != bool(config.get("key")):
            raise OpenStackPackError("profile cert_pem and key_pem must be supplied together")
        config["verify"] = True
        config["api_timeout"] = read_timeout
        config["connect_retries"] = 0
        config["status_code_retries"] = 0
        config_path = directory / "clouds.yaml"
        config_path.write_text(json.dumps({"clouds": {cloud: config}}, separators=(",", ":")), encoding="utf-8")
        os.chmod(config_path, 0o600)
        try:
            import openstack.config
            from openstack.connection import Connection

            loader = openstack.config.OpenStackConfig(
                config_files=[str(config_path)], secure_files=[], load_yaml_config=True,
                load_envvars=False, app_name="attune-openstack", app_version="0.1.0",
            )
            cloud_region = loader.get_one_cloud(cloud=cloud)
            cloud_region.config["api_timeout"] = (connect_timeout, read_timeout)
            connection = Connection(config=cloud_region, strict=True)
            actual_project = connection.current_project_id
            if not isinstance(actual_project, str) or actual_project.lower() != project_id:
                raise OpenStackPackError("authenticated project does not match requested project_id")
            scope = {
                "cloud": cloud, "region": region, "interface": interface,
                "project_id": project_id, "connect_timeout": connect_timeout,
                "read_timeout": read_timeout,
                "compute_api_version": config.get("compute_api_version"),
                "compute_default_microversion": config.get("compute_default_microversion"),
                "volume_api_version": config.get("volume_api_version"),
            }
        except OpenStackPackError:
            raise
        # Config, auth plugin, and transport setup errors may contain credentials.
        except Exception as exc:  # noqa: BLE001
            raise OpenStackPackError(f"OpenStack connection failed ({type(exc).__name__})") from None
        try:
            yield connection, scope
        finally:
            if connection is not None:
                try:
                    connection.close()
                # Cleanup cannot safely replace the primary action result.
                except Exception:  # noqa: BLE001, S110
                    pass


def _server(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    project_id = scope["project_id"]
    if operation == "server_list":
        maximum = _integer(params, "max_items", 100, 1, 1000)
        query = {}
        if params.get("status") is not None:
            query["status"] = _string(params["status"], "status", 32).upper()
        return _limited(conn.compute.servers(details=True, all_projects=False, **query), maximum, project_id)
    server_id = _uuid(params.get("server_id"), "server_id") if operation != "server_create" else None
    if operation == "server_get":
        server = conn.compute.get_server(server_id)
        _assert_owner(server, project_id)
        return _resource_dict(server)
    if operation == "server_create":
        name = _string(params.get("name"), "name")
        image_id = _uuid(params.get("image_id"), "image_id")
        flavor_id = _uuid(params.get("flavor_id"), "flavor_id")
        conn.image.get_image(image_id)
        conn.compute.get_flavor(flavor_id)
        network_ids = _uuid_list(params.get("network_ids", []), "network_ids", 8)
        port_ids = _uuid_list(params.get("port_ids", []), "port_ids", 8)
        if not network_ids and not port_ids:
            raise OpenStackPackError("one or more network_ids or port_ids are required")
        if network_ids and port_ids:
            raise OpenStackPackError("network_ids and port_ids are mutually exclusive")
        networks = []
        for resource_id in network_ids:
            network = conn.network.get_network(resource_id)
            _assert_owner(network, project_id)
            networks.append({"uuid": resource_id})
        for resource_id in port_ids:
            port = conn.network.get_port(resource_id)
            _assert_owner(port, project_id)
            networks.append({"port": resource_id})
        attrs: dict[str, Any] = {"name": name, "image_id": image_id, "flavor_id": flavor_id, "networks": networks}
        if params.get("key_name") is not None:
            attrs["key_name"] = _string(params["key_name"], "key_name")
        if params.get("availability_zone") is not None:
            attrs["availability_zone"] = _string(params["availability_zone"], "availability_zone")
        server = conn.compute.create_server(**attrs)
        _assert_owner(server, project_id)
        return {"accepted": True, "resource": _resource_dict(server)}
    server = conn.compute.get_server(server_id)
    _assert_owner(server, project_id)
    if operation == "server_wait":
        status = _string(params.get("status", "ACTIVE"), "status", 32).upper()
        timeout = _integer(params, "wait_timeout", 300, 1, 1800)
        interval = _integer(params, "poll_interval", 5, 1, 60)
        result = conn.compute.wait_for_server(server, status=status, failures=["ERROR"], interval=interval, wait=timeout)
        return _resource_dict(result)
    if operation == "server_start":
        conn.compute.start_server(server)
    elif operation == "server_stop":
        _confirm(params, f"STOP:{server_id}")
        conn.compute.stop_server(server)
    elif operation == "server_reboot":
        reboot_type = params.get("reboot_type", "SOFT")
        if reboot_type not in {"SOFT", "HARD"}:
            raise OpenStackPackError("reboot_type must be SOFT or HARD")
        _confirm(params, f"REBOOT:{server_id}:{reboot_type}")
        conn.compute.reboot_server(server, reboot_type)
    elif operation == "server_rebuild":
        image_id = _uuid(params.get("image_id"), "image_id")
        conn.image.get_image(image_id)
        _confirm(params, f"REBUILD:{server_id}:{image_id}")
        rebuilt = conn.compute.rebuild_server(server, image_id)
        return {"accepted": True, "resource": _resource_dict(rebuilt)}
    elif operation == "server_delete":
        _confirm(params, f"DELETE:{server_id}")
        conn.compute.delete_server(server, ignore_missing=False, force=False)
    else:
        raise OpenStackPackError("unsupported server action")
    return {"accepted": True, "resource": _resource_dict(server)}


def _image(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any], profile: dict[str, Any]) -> Any:
    if operation == "image_list":
        maximum = _integer(params, "max_items", 100, 1, 1000)
        query = {"visibility": params.get("visibility", "private")}
        if query["visibility"] not in {"private", "shared"}:
            raise OpenStackPackError("visibility must be private or shared")
        return _limited(conn.image.images(**query), maximum)
    if operation == "image_get":
        return _resource_dict(conn.image.get_image(_uuid(params.get("image_id"), "image_id")))
    if operation != "image_upload":
        raise OpenStackPackError("unsupported image action")
    path = _safe_artifact(profile, params.get("artifact_path"), existing=True)
    limit = _artifact_limit(profile, params)
    size = path.stat().st_size
    if size > limit:
        raise OpenStackPackError("image artifact exceeds max_bytes")
    disk_format = params.get("disk_format")
    if disk_format not in {"raw", "qcow2", "vhd", "vhdx", "vmdk", "vdi", "iso", "aki", "ari", "ami"}:
        raise OpenStackPackError("disk_format is not supported")
    visibility = params.get("visibility", "private")
    if visibility not in {"private", "shared"}:
        raise OpenStackPackError("visibility must be private or shared")
    container_format = params.get("container_format", "bare")
    if container_format not in {"bare", "ovf", "ova", "docker", "aki", "ari", "ami"}:
        raise OpenStackPackError("container_format is not supported")
    image = conn.image.create_image(
        _string(params.get("name"), "name"), filename=str(path), disk_format=disk_format,
        container_format=container_format, visibility=visibility,
        allow_duplicates=True, wait=False, size=size,
    )
    return {"accepted": True, "resource": _resource_dict(image), "bytes": size, "sha256": _sha256(path)}


NETWORK_SPECS = {
    "network_manage": ("network", "networks", {"name", "description", "admin_state_up", "port_security_enabled", "mtu"}),
    "subnet_manage": ("subnet", "subnets", {"network_id", "name", "description", "cidr", "ip_version", "enable_dhcp", "gateway_ip", "dns_nameservers", "allocation_pools"}),
    "router_manage": ("router", "routers", {"name", "description", "admin_state_up", "external_gateway_network_id"}),
    "port_manage": ("port", "ports", {"network_id", "name", "description", "admin_state_up", "fixed_ips", "security_group_ids", "port_security_enabled"}),
}


def _network_manage(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    singular, plural, allowed = NETWORK_SPECS[operation]
    verb = params.get("verb")
    if verb not in {"list", "get", "create", "update", "delete"}:
        raise OpenStackPackError("verb must be list, get, create, update, or delete")
    proxy = conn.network
    project_id = scope["project_id"]
    if verb == "list":
        return _limited(getattr(proxy, plural)(project_id=project_id), _integer(params, "max_items", 100, 1, 1000), project_id)
    resource_id = _uuid(params.get("resource_id"), "resource_id") if verb in {"get", "update", "delete"} else None
    if verb == "get":
        resource = getattr(proxy, f"get_{singular}")(resource_id)
        _assert_owner(resource, project_id)
        return _resource_dict(resource)
    attrs = {key: params[key] for key in allowed if key in params and params[key] is not None}
    if verb == "update":
        immutable = {"network_id", "cidr", "ip_version"} & set(attrs)
        if immutable:
            raise OpenStackPackError(f"update cannot change immutable field '{min(immutable)}'")
    for key in ("name", "description", "cidr", "gateway_ip"):
        if key in attrs:
            attrs[key] = _string(attrs[key], key, 1024)
    for key in ("admin_state_up", "port_security_enabled", "enable_dhcp"):
        if key in attrs and not isinstance(attrs[key], bool):
            raise OpenStackPackError(f"{key} must be a boolean")
    if "network_id" in attrs:
        attrs["network_id"] = _uuid(attrs["network_id"], "network_id")
        network = proxy.get_network(attrs["network_id"])
        _assert_owner(network, project_id)
    if "security_group_ids" in attrs:
        attrs["security_group_ids"] = _uuid_list(attrs["security_group_ids"], "security_group_ids", 16)
        for group_id in attrs["security_group_ids"]:
            _assert_owner(proxy.get_security_group(group_id), project_id)
    if "dns_nameservers" in attrs:
        attrs["dns_nameservers"] = _string_list(attrs["dns_nameservers"], "dns_nameservers", 8)
    if "allocation_pools" in attrs:
        pools = attrs["allocation_pools"]
        if (not isinstance(pools, list) or len(pools) > 16
                or any(not isinstance(pool, dict) or set(pool) != {"start", "end"} for pool in pools)):
            raise OpenStackPackError("allocation_pools must contain at most 16 start/end objects")
        attrs["allocation_pools"] = [
            {"start": _string(pool["start"], "allocation pool start", 64), "end": _string(pool["end"], "allocation pool end", 64)}
            for pool in pools
        ]
    if "fixed_ips" in attrs:
        fixed_ips = attrs["fixed_ips"]
        if not isinstance(fixed_ips, list) or len(fixed_ips) > 16 or any(not isinstance(item, dict) for item in fixed_ips):
            raise OpenStackPackError("fixed_ips must contain at most 16 objects")
        normalized = []
        for item in fixed_ips:
            if not set(item) <= {"subnet_id", "ip_address"} or "subnet_id" not in item:
                raise OpenStackPackError("each fixed_ips entry requires only subnet_id and optional ip_address")
            subnet_id = _uuid(item["subnet_id"], "fixed_ips subnet_id")
            _assert_owner(proxy.get_subnet(subnet_id), project_id)
            value = {"subnet_id": subnet_id}
            if item.get("ip_address") is not None:
                value["ip_address"] = _string(item["ip_address"], "fixed_ips ip_address", 64)
            normalized.append(value)
        attrs["fixed_ips"] = normalized
    if "mtu" in attrs and (isinstance(attrs["mtu"], bool) or not isinstance(attrs["mtu"], int) or not 68 <= attrs["mtu"] <= 65535):
        raise OpenStackPackError("mtu must be an integer from 68 to 65535")
    if "ip_version" in attrs and attrs["ip_version"] not in {4, 6}:
        raise OpenStackPackError("ip_version must be 4 or 6")
    subnet_network = None
    if "cidr" in attrs:
        try:
            subnet_network = ipaddress.ip_network(attrs["cidr"], strict=False)
        except ValueError:
            raise OpenStackPackError("cidr must be a valid IPv4 or IPv6 network") from None
        if "ip_version" in attrs and attrs["ip_version"] != subnet_network.version:
            raise OpenStackPackError("ip_version does not match cidr")
    if "gateway_ip" in attrs:
        try:
            gateway = ipaddress.ip_address(attrs["gateway_ip"])
        except ValueError:
            raise OpenStackPackError("gateway_ip must be a valid IP address") from None
        if subnet_network is not None and gateway not in subnet_network:
            raise OpenStackPackError("gateway_ip must be inside cidr")
    if "fixed_ips" in attrs:
        for fixed_ip in attrs["fixed_ips"]:
            if "ip_address" in fixed_ip:
                try:
                    ipaddress.ip_address(fixed_ip["ip_address"])
                except ValueError:
                    raise OpenStackPackError("fixed_ips ip_address must be a valid IP address") from None
    if "external_gateway_network_id" in attrs:
        network_id = _uuid(attrs.pop("external_gateway_network_id"), "external_gateway_network_id")
        proxy.get_network(network_id)
        attrs["external_gateway_info"] = {"network_id": network_id}
    if singular == "subnet" and verb == "create":
        if "network_id" not in attrs or "cidr" not in attrs:
            raise OpenStackPackError("subnet create requires network_id and cidr")
        attrs.setdefault("ip_version", 6 if ":" in attrs["cidr"] else 4)
    if singular == "port" and verb == "create" and "network_id" not in attrs:
        raise OpenStackPackError("port create requires network_id")
    if singular == "network" and verb == "create" and "name" not in attrs:
        raise OpenStackPackError("network create requires name")
    if verb == "create":
        attrs["project_id"] = project_id
        resource = getattr(proxy, f"create_{singular}")(**attrs)
    else:
        resource = getattr(proxy, f"get_{singular}")(resource_id)
        _assert_owner(resource, project_id)
        if verb == "delete":
            _confirm(params, f"DELETE:{resource_id}")
            getattr(proxy, f"delete_{singular}")(resource, ignore_missing=False)
            return {"accepted": True, "resource": _resource_dict(resource)}
        if not attrs:
            raise OpenStackPackError("update requires at least one supported field")
        resource = getattr(proxy, f"update_{singular}")(resource, **attrs)
    _assert_owner(resource, project_id)
    return _resource_dict(resource)


def _security(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    proxy = conn.network
    project_id = scope["project_id"]
    rule = operation == "security_group_rule_manage"
    singular = "security_group_rule" if rule else "security_group"
    plural = "security_group_rules" if rule else "security_groups"
    verbs = {"list", "get", "create", "delete"} if rule else {"list", "get", "create", "update", "delete"}
    verb = params.get("verb")
    if verb not in verbs:
        raise OpenStackPackError(f"verb must be one of {', '.join(sorted(verbs))}")
    if verb == "list":
        query = {"project_id": project_id}
        if rule and params.get("security_group_id"):
            query["security_group_id"] = _uuid(params["security_group_id"], "security_group_id")
        return _limited(getattr(proxy, plural)(**query), _integer(params, "max_items", 100, 1, 1000), project_id)
    resource_id = _uuid(params.get("resource_id"), "resource_id") if verb != "create" else None
    if verb == "get":
        resource = getattr(proxy, f"get_{singular}")(resource_id)
        _assert_owner(resource, project_id)
        return _resource_dict(resource)
    if verb == "create":
        if rule:
            group_id = _uuid(params.get("security_group_id"), "security_group_id")
            _assert_owner(proxy.get_security_group(group_id), project_id)
            direction = params.get("direction", "ingress")
            ethertype = params.get("ethertype", "IPv4")
            if direction not in {"ingress", "egress"} or ethertype not in {"IPv4", "IPv6"}:
                raise OpenStackPackError("invalid security rule direction or ethertype")
            attrs: dict[str, Any] = {"security_group_id": group_id, "direction": direction, "ethertype": ethertype, "project_id": project_id}
            for key in ("protocol", "remote_ip_prefix", "remote_group_id", "description"):
                if params.get(key) is not None:
                    attrs[key] = _string(params[key], key, 1024)
            if "remote_group_id" in attrs:
                attrs["remote_group_id"] = _uuid(attrs["remote_group_id"], "remote_group_id")
                _assert_owner(proxy.get_security_group(attrs["remote_group_id"]), project_id)
            if "remote_ip_prefix" in attrs:
                try:
                    remote = ipaddress.ip_network(attrs["remote_ip_prefix"], strict=False)
                except ValueError:
                    raise OpenStackPackError("remote_ip_prefix must be a valid CIDR") from None
                if remote.version != (4 if ethertype == "IPv4" else 6):
                    raise OpenStackPackError("remote_ip_prefix does not match ethertype")
            for key in ("port_range_min", "port_range_max"):
                if params.get(key) is not None:
                    attrs[key] = _integer(params, key, 0, 0, 65535)
            has_min = "port_range_min" in attrs
            has_max = "port_range_max" in attrs
            if has_min != has_max or (has_min and attrs["port_range_min"] > attrs["port_range_max"]):
                raise OpenStackPackError("port_range_min and port_range_max must be supplied together in ascending order")
        else:
            attrs = {"name": _string(params.get("name"), "name"), "project_id": project_id}
            if params.get("description") is not None:
                attrs["description"] = _string(params["description"], "description", 1024)
        resource = getattr(proxy, f"create_{singular}")(**attrs)
        _assert_owner(resource, project_id)
        return _resource_dict(resource)
    resource = getattr(proxy, f"get_{singular}")(resource_id)
    _assert_owner(resource, project_id)
    if verb == "delete":
        _confirm(params, f"DELETE:{resource_id}")
        getattr(proxy, f"delete_{singular}")(resource, ignore_missing=False)
        return {"accepted": True, "resource": _resource_dict(resource)}
    attrs = {}
    for key in ("name", "description"):
        if params.get(key) is not None:
            attrs[key] = _string(params[key], key, 1024)
    if not attrs:
        raise OpenStackPackError("update requires name or description")
    return _resource_dict(proxy.update_security_group(resource, **attrs))


def _floating(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    proxy = conn.network
    project_id = scope["project_id"]
    if operation == "floating_ip_allocate":
        network_id = _uuid(params.get("network_id"), "network_id")
        proxy.get_network(network_id)
        attrs = {"floating_network_id": network_id, "project_id": project_id}
        if params.get("description") is not None:
            attrs["description"] = _string(params["description"], "description", 1024)
        resource = proxy.create_ip(**attrs)
        _assert_owner(resource, project_id)
        return _resource_dict(resource)
    floating_id = _uuid(params.get("floating_ip_id"), "floating_ip_id")
    resource = proxy.get_ip(floating_id)
    _assert_owner(resource, project_id)
    if operation == "floating_ip_associate":
        port_id = _uuid(params.get("port_id"), "port_id")
        _assert_owner(proxy.get_port(port_id), project_id)
        data = _resource_dict(resource)
        fixed = params.get("fixed_ip_address")
        if data.get("port_id") == port_id and (fixed is None or data.get("fixed_ip_address") == fixed):
            return {"unchanged": True, "resource": data}
        if data.get("port_id"):
            raise OpenStackPackError("floating IP is already associated with another port")
        attrs = {"port_id": port_id}
        if fixed is not None:
            attrs["fixed_ip_address"] = _string(fixed, "fixed_ip_address", 64)
        return _resource_dict(proxy.update_ip(resource, **attrs))
    if operation == "floating_ip_release":
        attached = _resource_dict(resource).get("port_id")
        expected = f"RELEASE:{floating_id}" + (f":{attached}" if attached else "")
        _confirm(params, expected)
        proxy.delete_ip(resource, ignore_missing=False)
        return {"accepted": True, "resource": _resource_dict(resource)}
    raise OpenStackPackError("unsupported floating IP action")


def _volume(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    project_id = scope["project_id"]
    if operation == "volume_list":
        return _limited(conn.block_storage.volumes(details=True, project_id=project_id), _integer(params, "max_items", 100, 1, 1000), project_id)
    if operation == "volume_create":
        attrs: dict[str, Any] = {
            "name": _string(params.get("name"), "name"),
            "size": _integer(params, "size_gib", 1, 1, 1024),
        }
        for key in ("description", "availability_zone", "volume_type"):
            if params.get(key) is not None:
                attrs[key] = _string(params[key], key)
        resource = conn.block_storage.create_volume(**attrs)
        _assert_owner(resource, project_id)
        return {"accepted": True, "resource": _resource_dict(resource)}
    volume_id = _uuid(params.get("volume_id"), "volume_id")
    volume = conn.block_storage.get_volume(volume_id)
    _assert_owner(volume, project_id)
    if operation == "volume_get":
        return _resource_dict(volume)
    if operation == "volume_delete":
        _confirm(params, f"DELETE:{volume_id}")
        if _resource_dict(volume).get("attachments"):
            raise OpenStackPackError("attached volume cannot be deleted")
        conn.block_storage.delete_volume(volume, ignore_missing=False, force=False)
        return {"accepted": True, "resource": _resource_dict(volume)}
    server_id = _uuid(params.get("server_id"), "server_id")
    server = conn.compute.get_server(server_id)
    _assert_owner(server, project_id)
    if operation == "volume_attach":
        device = params.get("device")
        if device is not None:
            device = _string(device, "device", 255)
        attachment = conn.compute.create_volume_attachment(server, volume, device=device)
        return {"accepted": True, "resource": _resource_dict(attachment)}
    if operation == "volume_detach":
        conn.compute.get_volume_attachment(server, volume)
        _confirm(params, f"DETACH:{volume_id}:{server_id}")
        conn.compute.delete_volume_attachment(server, volume, ignore_missing=False)
        return {"accepted": True, "volume_id": volume_id, "server_id": server_id}
    raise OpenStackPackError("unsupported volume action")


class _CappedWriter:
    def __init__(self, handle: Any, maximum: int):
        self.handle = handle
        self.maximum = maximum
        self.count = 0

    def write(self, data: bytes) -> int:
        self.count += len(data)
        if self.count > self.maximum:
            raise OpenStackPackError("object download exceeds max_bytes")
        return self.handle.write(data)

    def flush(self) -> None:
        self.handle.flush()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object_store(conn: Any, operation: str, params: dict[str, Any], profile: dict[str, Any]) -> Any:
    container = _string(params.get("container"), "container", 256)
    if operation == "object_list":
        maximum = _integer(params, "max_items", 100, 1, 1000)
        query: dict[str, Any] = {"limit": maximum + 1}
        for key in ("prefix", "marker"):
            if params.get(key) is not None:
                query[key] = _string(params[key], key, 1024)
        return _limited(conn.object_store.objects(container, **query), maximum)
    name = _string(params.get("object_name"), "object_name", 1024)
    path = _safe_artifact(profile, params.get("artifact_path"), existing=operation == "object_upload")
    maximum = _artifact_limit(profile, params)
    if operation == "object_upload":
        _confirm(params, f"UPLOAD:{container}/{name}")
        size = path.stat().st_size
        if size > maximum:
            raise OpenStackPackError("object artifact exceeds max_bytes")
        resource = conn.object_store.create_object(container, name, filename=str(path), generate_checksums=True)
        return {"accepted": True, "resource": _resource_dict(resource), "bytes": size, "sha256": _sha256(path)}
    if operation == "object_download":
        if path.exists():
            _confirm(params, f"OVERWRITE:{params.get('artifact_path')}")
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".attune-openstack-", dir=path.parent, delete=False) as handle:
                temporary_path = Path(handle.name)
                writer = _CappedWriter(handle, maximum)
                resource = conn.object_store.get_object(name, container=container, outfile=writer, resp_chunk_size=1024 * 1024)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, path)
            temporary_path = None
            return {"resource": _resource_dict(resource), "path": str(params.get("artifact_path")), "bytes": writer.count, "sha256": _sha256(path)}
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
    raise OpenStackPackError("unsupported object action")


def _template(params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    template = _dict(params.get("template"), "template", 10000)
    environment = params.get("environment")
    if environment is not None:
        environment = _dict(environment, "environment", 10000)
    if len(json.dumps({"template": template, "environment": environment}).encode()) > MAX_TEMPLATE_BYTES:
        raise OpenStackPackError("template and environment exceed the 1 MiB action limit")
    resources = template.get("resources", {})
    if not isinstance(resources, dict):
        raise OpenStackPackError("template resources must be an object")
    if len(resources) > MAX_HEAT_RESOURCES:
        raise OpenStackPackError(f"template exceeds the {MAX_HEAT_RESOURCES}-resource action limit")
    return template, environment


def _stack(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any]) -> Any:
    proxy = conn.orchestration
    project_id = scope["project_id"]
    if operation == "stack_validate":
        template, environment = _template(params)
        validated = proxy.validate_template(template, environment=environment)
        raw = validated.to_dict(computed=False) if hasattr(validated, "to_dict") else dict(validated)
        parameters = raw.get("parameters") or raw.get("Parameters") or {}
        if not isinstance(parameters, dict):
            parameters = {}
        return {
            "valid": True,
            "description": raw.get("description") or raw.get("Description"),
            "parameter_names": sorted(str(name) for name in parameters),
        }
    if operation == "stack_create":
        template, environment = _template(params)
        attrs: dict[str, Any] = {
            "name": _string(params.get("name"), "name"), "template": template,
            "timeout_mins": _integer(params, "timeout_mins", 60, 1, 1440),
            "disable_rollback": False,
        }
        if environment is not None:
            attrs["environment"] = environment
        stack = proxy.create_stack(**attrs)
        _assert_owner(stack, project_id)
        return {"accepted": True, "resource": _resource_dict(stack)}
    stack_id = _uuid(params.get("stack_id"), "stack_id")
    stack = proxy.get_stack(stack_id, resolve_outputs=False)
    _assert_owner(stack, project_id)
    if operation == "stack_status":
        return _resource_dict(stack)
    if operation == "stack_update":
        template, environment = _template(params)
        _confirm(params, f"UPDATE:{stack_id}")
        attrs = {"template": template}
        if environment is not None:
            attrs["environment"] = environment
        updated = proxy.update_stack(stack, **attrs)
        return {"accepted": True, "resource": _resource_dict(updated)}
    if operation == "stack_delete":
        _confirm(params, f"DELETE:{stack_id}")
        proxy.delete_stack(stack, ignore_missing=False)
        return {"accepted": True, "resource": _resource_dict(stack)}
    raise OpenStackPackError("unsupported stack action")


def _dispatch(conn: Any, operation: str, params: dict[str, Any], scope: dict[str, Any], profile: dict[str, Any]) -> Any:
    if operation == "identity_current":
        project_id = scope["project_id"]
        project = conn.identity.get_project(project_id)
        _assert_owner(project, project_id)
        return {
            "project": _resource_dict(project),
            "project_id": project_id,
            "user_id": conn.current_user_id,
        }
    if operation.startswith("server_"):
        return _server(conn, operation, params, scope)
    if operation.startswith("image_"):
        return _image(conn, operation, params, scope, profile)
    if operation in NETWORK_SPECS:
        return _network_manage(conn, operation, params, scope)
    if operation in {"security_group_manage", "security_group_rule_manage"}:
        return _security(conn, operation, params, scope)
    if operation.startswith("floating_ip_"):
        return _floating(conn, operation, params, scope)
    if operation.startswith("volume_"):
        return _volume(conn, operation, params, scope)
    if operation.startswith("object_"):
        return _object_store(conn, operation, params, profile)
    if operation.startswith("stack_"):
        return _stack(conn, operation, params, scope)
    raise OpenStackPackError("unsupported OpenStack action")


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    profile = _fetch_key(params.get("profile_key", DEFAULT_PROFILE_KEY))
    try:
        with _connection(profile, params) as (conn, scope):
            data = _dispatch(conn, operation, params, scope, profile)
            result = {"operation": operation, "data": data, "scope": scope}
            if len(json.dumps(result, default=str).encode()) > MAX_OUTPUT_BYTES:
                raise OpenStackPackError("structured output exceeds the 8 MiB action limit")
            return result
    except OpenStackPackError:
        raise
    # SDK exception messages can include request headers and response bodies.
    except Exception as exc:  # noqa: BLE001
        raise OpenStackPackError(f"OpenStack operation failed ({type(exc).__name__})") from None
