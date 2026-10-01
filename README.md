# OpenStack Attune Pack

This pack adapts the Apache-2.0 StackStorm Exchange OpenStack pack at revision
`719b93fe95c091d3e75364af66172b6cae68a370`. It replaces exactly 710 stale,
generated CLI actions and many duplicated service-client dependencies with 36
curated actions over `openstacksdk 4.18.x`. The legacy Zaqar sensor is not
ported. See [SOURCE.md](SOURCE.md) for the source and API baseline.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- `openstacksdk>=4.18.0,<5`, installed from `requirements.txt`.
- Network access to the selected OpenStack service catalog endpoints.
- A pack-owned encrypted Attune Key, normally `pack.openstack.profile`.
- Least-privilege OpenStack roles and sufficient service quotas.
- A private worker artifact directory for image and object transfer actions.

## Profile and Scope

Create the Key with local ref `profile`, owner type `pack`, and
`owner_pack_ref` `openstack`. Its canonical ref is `pack.openstack.profile`.
The Key contains a named cloud and one current `clouds.yaml`-style cloud
mapping. Host `clouds.yaml`, `secure.yaml`, and `OS_*` environment variables
are deliberately ignored. This avoids ambient worker credentials and region or
project drift.

Application credential example:

```json
{
  "cloud": "production",
  "config": {
    "auth_type": "v3applicationcredential",
    "auth": {
      "auth_url": "https://identity.example.com/v3",
      "application_credential_id": "REDACTED_APPLICATION_CREDENTIAL_ID",
      "application_credential_secret": "REDACTED_APPLICATION_CREDENTIAL_SECRET",
      "project_id": "0123456789abcdef0123456789abcdef"
    },
    "region_name": "RegionOne",
    "interface": "internal",
    "verify": true,
    "compute_api_version": "2",
    "compute_default_microversion": "2.79",
    "volume_api_version": "3"
  },
  "artifact_root": "/var/lib/attune/artifacts/openstack",
  "max_artifact_bytes": 10737418240
}
```

For a private CA, add `cacert_pem` to `config`. Mutual TLS additionally uses
`cert_pem` and `key_pem` together. Worker paths in `cacert`, `cert`, and `key`
are rejected. The pack writes a JSON document that is also valid
`clouds.yaml`, plus any PEM material, into a mode-0700 temporary directory;
files are mode 0600 and remain only for the connection lifetime. This temporary
configuration is necessary to preserve SDK named-cloud and vendor-profile
semantics without allowing ambient configuration.

TLS verification cannot be disabled. `auth_url` must use HTTPS and may not
contain user information, query parameters, or fragments. Every action must
repeat the expected `cloud`, `region`, `interface`, and project ID. The action
authenticates and rejects the request before service use if the actual scoped
project differs.

`connect_timeout` is bounded to 1-30 seconds and `read_timeout` to 1-300
seconds. They are supplied to the underlying requests session as separate
connect/read values. SDK connection and HTTP status retries are set to zero;
mutation outcomes are never guessed or blindly replayed.

## Actions

| Area | Actions |
|---|---|
| Identity | `identity_current` |
| Servers | `server_list`, `server_get`, `server_create`, `server_start`, `server_stop`, `server_reboot`, `server_rebuild`, `server_delete`, `server_wait` |
| Images | `image_list`, `image_get`, `image_upload` |
| Networking | `network_manage`, `subnet_manage`, `router_manage`, `port_manage` |
| Security | `security_group_manage`, `security_group_rule_manage` |
| Floating IPs | `floating_ip_allocate`, `floating_ip_associate`, `floating_ip_release` |
| Volumes | `volume_list`, `volume_get`, `volume_create`, `volume_attach`, `volume_detach`, `volume_delete` |
| Object storage | `object_list`, `object_upload`, `object_download` |
| Heat | `stack_validate`, `stack_create`, `stack_update`, `stack_status`, `stack_delete` |

Manage actions use an explicit `verb`. Existing OpenStack resources are always
resolved by ID; names are accepted only when creating a resource or where the
service itself addresses data by name, such as a Swift container/object key.
No create-or-find behavior, cross-project search, admin `all_projects`, force
delete, force detach, public image publication, provider network mutation, or
router-interface shortcut is exposed.

Every action receives one flat JSON object on stdin and returns:

```json
{
  "operation": "server_get",
  "data": {"id": "...", "name": "web", "status": "ACTIVE"},
  "scope": {
    "cloud": "production",
    "region": "RegionOne",
    "interface": "internal",
    "project_id": "0123456789abcdef0123456789abcdef",
    "connect_timeout": 10,
    "read_timeout": 60,
    "compute_api_version": "2",
    "compute_default_microversion": "2.79",
    "volume_api_version": "3"
  }
}
```

Outputs use an allowlist and omit tokens, passwords, generated administrator
passwords, server metadata, Heat parameters/templates/outputs, and arbitrary
response bodies. Unknown SDK and transport exceptions are reduced to their
class name. Output is capped at 8 MiB.

## Safety Contracts

- List output defaults to 100 items and is capped at 1000. `truncated` and a
  best-effort `next_marker` are returned where applicable.
- Server wait is a read-only bounded poll: 1-1800 seconds total and 1-60
  seconds between polls. Asynchronous create/mutate/delete actions return
  `accepted: true`; callers inspect the relevant get/status action.
- Server creation accepts one request with at most eight explicit network or
  port IDs. Network and port modes cannot be mixed.
- Volume size is capped at 1024 GiB per action. Attached volumes cannot be
  deleted, and force delete/detach are unavailable.
- Heat template plus environment is capped at 1 MiB and 100 declared
  resources. Rollback remains enabled.
- `compute_default_microversion` and service API versions stay in the Key
  profile and are reported in every result. Operators must select versions
  supported by their cloud; the SDK performs normal negotiation.
- Destructive actions require exact confirmation strings such as
  `DELETE:<id>`, `REBUILD:<server_id>:<image_id>`, or
  `DETACH:<volume_id>:<server_id>`.
- Floating IP release confirmation includes the attached port ID when one is
  present, making an implicit detach visible to the caller.

## Artifact Confinement

Image and object paths are relative to the profile `artifact_root`. Absolute
paths, `.`/`..` segments, missing parents, symlink escapes, and non-regular
upload files are rejected. Upload size is checked before mutation. Downloads
stream through a capped private temporary file in the destination directory,
are fsynced, and are atomically renamed only after success. Existing targets
require `OVERWRITE:<artifact_path>`. Interrupted or oversized downloads remove
the temporary file.

Object upload always requires `UPLOAD:<container>/<object_name>` because Swift
PUT replaces an existing key. Object and image results include local byte count
and SHA-256 without returning artifact data.

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q actions lib tests
attune --output json pack check /home/david/Codebase/attune-packs/openstack
attune pack test /home/david/Codebase/attune-packs/openstack --detailed
```

Tests use deterministic fake SDK proxies and mocked Attune Key access. No cloud
or undeclared package is required. Live validation remains deployment-specific
because Keystone auth plugins, service policy, quotas, microversions, Glance
import behavior, Swift limits, Heat resources, TLS PKI, and endpoint catalogs
vary by cloud.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
