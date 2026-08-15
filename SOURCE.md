# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-openstack
- Upstream pack version at revision: `1.0.1`
- Verified revision: `719b93fe95c091d3e75364af66172b6cae68a370`
- Revision date: `2021-12-19T01:26:46-06:00`
- Revision tag status: untagged; latest upstream release tag is `v1.0.1` at `ec7c5abcb8a3f9a3cbd9811d741a1fdeb159c2b3`
- Revision signature: Git reports a good signature made with expired key `1A72D048C9AA75BE`; GitHub reports `unknown_key` and does not mark the commit verified
- Upstream license: Apache License 2.0 (`LICENSE` blob `8dada3edaf50dbc082c9a125058f25def75e625a`)
- Upstream NOTICE: none at the verified revision
- Upstream inventory: exactly 710 action YAML files and 5 shared Python files
- SDK baseline reviewed: `openstacksdk 4.18.0`, current PyPI release on 2026-08-14

The upstream implementation wraps a 2021-era `python-openstackclient` plus
service-specific Nova, Neutron, Keystone, Glance, Swift, Cinder, Heat,
Ceilometer, Aodh, and Zaqar clients. This adaptation uses the current unified
OpenStack SDK and named-cloud configuration semantics instead.

Authoritative references:

- https://docs.openstack.org/openstacksdk/latest/user/config/configuration.html
- https://docs.openstack.org/openstacksdk/latest/user/connection.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/compute.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/network.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/image.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/block_storage_v3.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/object_store.html
- https://docs.openstack.org/openstacksdk/latest/user/proxies/orchestration.html

Deliberate omissions include the 710 generated CLI wrappers, overlapping
Neutron/openstack commands, shell RC and environment-variable authentication
examples, administrative surfaces, telemetry clients, and the Zaqar sensor.
No upstream source file was copied into the runtime implementation; action
selection and requirements were adapted and attribution is retained.
