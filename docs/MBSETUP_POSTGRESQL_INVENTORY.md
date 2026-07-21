# mbsetup PostgreSQL Migration Inventory

Status: B5.3 inventory baseline, 2026-07-21

## Purpose

`mbsetup` is currently a collection of editors for native C-structure files,
menu assets, generated documentation and runtime directories. The long-term
FortyTwo BBS target is not to let a desktop manager or terminal program connect
directly to PostgreSQL. Structured administrative state will be owned by
PostgreSQL and changed through a versioned local or remote administration
service with authorization and audit logging.

This document records the current direct-storage boundary before migration.
It is an inventory, not an approval of the legacy formats.

## Architectural boundary

The intended flow is:

```text
mbsetup / future native manager
            |
            | authenticated admin operations
            v
FortyTwo administration service
            |
            | narrowly scoped PostgreSQL role
            v
PostgreSQL authoritative state
```

PostgreSQL is intended to become authoritative for structured configuration,
identity, permissions, areas, routing and operational metadata. Payload files
such as ANSI screens, text resources, executable tools, inbound/outbound mail,
download archives and logs remain filesystem objects. PostgreSQL may reference
and describe those objects; it does not need to contain every payload byte.

## Source baseline

The current `mbsetup` source contains:

- 31 distinct `MBSE_ROOT`-relative `*.data` path patterns;
- 26 stores using the usual `.data` / `.temp` snapshot-editor model;
- 5 stores with special access models;
- 30 source modules that reference at least one structured legacy store;
- additional menu and language assets outside the `*.data` inventory.

Run the source-controlled baseline check with:

```text
python3 scripts/check_mbsetup_storage_inventory.py
```

A newly introduced or moved direct legacy-store access must fail that check
until the inventory and migration plan are deliberately updated.

## Structured legacy stores

| Legacy path | Direct mbsetup source owners | Current role | Migration domain | Wave |
|---|---|---|---|---:|
| `etc/users.data` | `m_limits.c`, `m_users.c` | User profiles, status, statistics and legacy authorization fields | Identity/profile compatibility | 1 |
| `etc/limits.data` | `m_limits.c`, `m_users.c` | Security-level limits and usage policy | Authorization and usage policy | 1 |
| `etc/config.data` | `m_global.c` | One large mixed global configuration structure | Split global configuration | 2 |
| `etc/mgroups.data` | `m_marea.c`, `m_mgroup.c`, `m_node.c` | Message-group topology | Message topology | 3 |
| `etc/mareas.data` | `m_marea.c`, `m_mgroup.c`, `m_node.c` | Message-area definitions and access rules | Message topology | 3 |
| `etc/fgroups.data` | `m_fgroup.c`, `m_ngroup.c`, `m_node.c`, `m_ticarea.c` | File-group topology | File topology | 3 |
| `etc/fareas.data` | `m_farea.c`, `m_fdb.c`, `m_ff.c`, `m_fgroup.c`, `m_ngroup.c`, `m_ticarea.c` | File-area definitions and access rules | File topology | 3 |
| `etc/newfiles.data` | `m_marea.c`, `m_new.c`, `m_ngroup.c` | New-file report definitions | File reporting | 3 |
| `etc/ngroups.data` | `m_new.c`, `m_ngroup.c` | New-file report groups | File reporting | 3 |
| `etc/scanmgr.data` | `m_ff.c`, `m_marea.c` | FileFind and scan-manager configuration | File search/reporting | 3 |
| `etc/tic.data` | `m_farea.c`, `m_fdb.c`, `m_fgroup.c`, `m_node.c`, `m_ticarea.c` | File-echo area definitions | File-echo topology | 3 |
| `etc/hatch.data` | `m_hatch.c`, `m_ticarea.c` | Hatch manager definitions | File-echo automation | 3 |
| `etc/magic.data` | `m_magic.c`, `m_ticarea.c` | Magic-file processing definitions | File-echo automation | 3 |
| `etc/fidonet.data` | `m_fido.c`, `m_node.c` | FTN network definitions | FTN/network topology | 4 |
| `etc/nodes.data` | `m_fgroup.c`, `m_marea.c`, `m_mgroup.c`, `m_node.c`, `m_ticarea.c` | FTN node configuration and subscriptions | FTN/network topology | 4 |
| `etc/domain.data` | `m_domain.c` | Domain definitions | FTN/network topology | 4 |
| `etc/domalias.data` | `m_domalias.c` | Domain aliases | FTN/network topology | 4 |
| `etc/route.data` | `m_route.c` | Routing rules | FTN/network topology | 4 |
| `etc/modem.data` | `m_modem.c` | Legacy modem types | Transport configuration | 5 |
| `etc/ttyinfo.data` | `m_modem.c`, `m_tty.c` | TTY line definitions | Transport configuration | 5 |
| `etc/protocol.data` | `m_protocol.c` | File-transfer protocol definitions | Transport/tool policy | 5 |
| `etc/service.data` | `m_service.c` | Service command definitions | Service policy | 5 |
| `etc/ibcsrv.data` | `m_ibc.c` | Internet BBS chat server definitions | Service policy | 5 |
| `etc/task.data` | `m_task.c` | Task-manager commands and thresholds | Scheduler policy | 5 |
| `etc/archiver.data` | `m_archive.c` | Archive command definitions | Executable tool policy | 5 |
| `etc/virscan.data` | `m_virus.c` | Virus-scanner command definitions | Executable tool policy | 5 |
| `etc/language.data` | `m_lang.c`, `m_menu.c` | Language metadata and resource paths | Presentation metadata | 6 |
| `etc/oneline.data` | `m_ol.c` | Oneliner content | BBS content | 6 |
| `etc/sysinfo.data` | `m_marea.c` | Read-only system information consumed by the area editor | Derived/runtime metadata | 6 |
| `var/fdb/file%d.data` | `m_farea.c`, `m_fdb.c` | Per-area file records | File catalogue | 6 |
| `var/fdb/fdb%d.data` | `m_fdb.c` | Per-area file database/index metadata | File catalogue/index | 6 |

## Access-model split

### Snapshot-style stores

Twenty-six stores use a variant of this lifecycle:

```text
source.data -> source.temp -> edit records -> replace source.data
```

The B5.2 `users.data` hardening is the first secured implementation of this
pattern. It is not a reason to reproduce the same pattern for PostgreSQL.
Each migrated editor must use explicit database transactions and revision or
conflict checks.

### Special-access stores

The following stores do not follow the ordinary snapshot model:

- `config.data`: a large mixed structure is read and written as global state;
- `task.data`: task configuration is rewritten directly;
- `sysinfo.data`: read-only cross-input for message-area setup;
- `var/fdb/file%d.data`: direct per-area file-record editing;
- `var/fdb/fdb%d.data`: direct per-area file database/index maintenance.

These stores require dedicated migration designs rather than a generic file
wrapper.

## Cross-module dependency hotspots

Migration cannot safely proceed by replacing only the obvious editor module.
Several stores are read by other editors for validation and cross-references:

- `fareas.data`: 6 source modules;
- `nodes.data`: 5 source modules;
- `tic.data`: 5 source modules;
- `fgroups.data`: 4 source modules;
- `mareas.data`, `mgroups.data`, `newfiles.data`: 3 source modules each.

A migrated store therefore needs a shared repository/service interface before
its legacy readers can be removed.

## Non-`*.data` administrative state

`mbsetup` also manages or generates filesystem-backed state that is outside the
31-store baseline:

- language-specific menu files under `share/int/menus/` (`*.mnu`, temporary
  `*.tmp` files);
- language, macro and text resource directories;
- generated site documentation and helper files such as `msg.txt` and
  `golded.inc`;
- mail, queue, rules, boxes and transfer directories;
- executable paths for archivers, scanners, protocols and task commands.

These objects must be inventoried by ownership and purpose, but they are not all
candidates for storing as PostgreSQL byte arrays. The database should hold
structured metadata, versioning, references and audit information while the
filesystem remains the payload store where appropriate.

## Migration rules

1. PostgreSQL becomes authoritative one domain at a time.
2. No editor may silently write both PostgreSQL and a legacy file without an
   explicit compatibility contract and failure policy.
3. Every operation must document the legacy reads/writes, affected fields,
   PostgreSQL transaction and compatibility output.
4. `mbsetup` must not receive unrestricted database credentials.
5. Future Haiku, Linux, Windows or web managers use the same versioned admin
   service; they never connect directly to PostgreSQL.
6. All administrative writes require authorization, audit logging and
   optimistic revision/conflict handling.
7. A migrated domain must retain a tested read-only or export path for legacy
   compatibility until every runtime consumer has moved.

## Planned migration sequence

### Wave 1: identity and authorization boundary

- map every `m_users.c` field to PostgreSQL or a declared legacy-only field;
- move limits and authorization semantics out of `limits.data`;
- identify authentication and new-user defaults embedded in `config.data`;
- provide admin-service operations for user/profile/role/transport changes;
- retain `users.data` only as an explicit compatibility projection.

### Wave 2: decompose global configuration

Split `config.data` into stable domains instead of reproducing one giant SQL
row or binary blob. Separate identity policy, presentation, paths, logging,
runtime limits and FTN defaults.

### Wave 3: message and file topology

Introduce shared PostgreSQL-backed repositories for groups, areas, access
rules, subscriptions and report definitions. Migrate all cross-readers together
with each authoritative store.

### Wave 4: FTN and routing topology

Migrate networks, nodes, domains, aliases and routing rules with foreign keys,
validation and revision tracking.

### Wave 5: operational commands and services

Migrate executable command definitions, protocols, scanners, archivers,
scheduler and transport configuration. Treat command paths and arguments as a
security policy, not merely strings copied from old records.

### Wave 6: file catalogue and presentation assets

Migrate file catalogue metadata and indexes. Decide separately whether menu and
text resources remain versioned filesystem assets or become service-managed
content records.

## Immediate next step

The first field-level inventory is `m_users.c` plus the user-related portions of
`limits.data` and `config.data`. That inventory must distinguish:

- PostgreSQL-authoritative identity and profile fields;
- roles, capabilities and transport access;
- runtime statistics and session-derived values;
- user preferences;
- obsolete Unix-account fields;
- legacy-only compatibility fields;
- fields that must never be copied back from legacy state into PostgreSQL.
