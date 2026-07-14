```text
___________            __          ___________               ____________________  _________
\_   _____/___________/  |_ ___.__.\__    ___/_  _  ______   \______   \______   \/   _____/
 |    __)/  _ \_  __ \   __<   |  |  |    |  \ \/ \/ /  _ \   |    |  _/|    |  _/\_____  \
 |     \(  <_> )  | \/|  |  \___  |  |    |   \     (  <_> )  |    |   \|    |   \/        \
 \___  / \____/|__|   |__|  / ____|  |____|    \/\_/ \____/   |______  /|______  /_______  /
     \/                     \/                                       \/        \/        \/
```

[Deutsche Fassung](LIESMICH.md)

> [!CAUTION]
> ## Development status: Pre-alpha - testing only
>
> FortyTwo BBS is currently undergoing extensive modernization, security
> review and testing.
>
> This repository is not intended for production use, the operation of a
> publicly accessible BBS, or use on production systems or production
> hardware.
>
> Do not install or run this software on systems that contain valuable,
> unique, personal, business-critical or otherwise irreplaceable data. Use it
> only in an isolated test environment, preferably on a dedicated test
> machine, virtual machine or rootless container. Maintain current,
> independently stored backups of all affected data and configurations.
>
> Before using the software, you are responsible for carrying out your own
> risk assessment, determining appropriate technical and organizational
> safeguards, and deciding whether the software is suitable for the intended
> environment. Use of the software is entirely at your own risk.
>
> The software may contain crashes, memory errors, security vulnerabilities,
> incomplete migrations, incompatible configuration changes and other
> defects. It is provided without any guarantee of functionality,
> availability, compatibility, security or fitness for a particular purpose.
>
> To the maximum extent permitted by applicable law, the authors and
> contributors accept no liability for data loss, data corruption, loss of
> use, system failure, security incidents, business interruption, loss of
> profits, or costs arising from recovery, restoration, reconstruction,
> reinstallation or replacement procurement.
>
> Nothing in this notice excludes or limits liability where such exclusion or
> limitation is prohibited by applicable law, including liability for
> intentional misconduct, gross negligence, or injury to life, body or
> health.
>
> This notice supplements, but does not replace, the terms of the applicable
> open-source license.
>
> A first public test release is currently planned for late 2026.

---

**FortyTwo BBS** is a modern continuation of **MBSE BBS**, an open-source
Bulletin Board System written in C for Linux and BSD.

The project is based on **MBSE BBS 1.1.7.2** and preserves its extensive
Fidonet, filebase, mail and door functionality while gradually improving
portability, safety, administration and usability.

> The answer may be 42. The BBS still needs a sysop.

## Project status

FortyTwo BBS is currently in an early development and code-review phase.

The existing MBSE codebase is being tested, documented and modernized
incrementally. Compatibility with existing MBSE installations and data
formats remains an important goal.

Internal program names, paths and configuration structures may still use the
original `mbse` naming.

The current implementation still contains transitional authentication and
identity-handling code inherited from MBSE BBS. This code is being contained
and replaced step by step. It must not be mistaken for the final FortyTwo BBS
security model.

## Security architecture

The target architecture uses:

- rootless Podman
- fixed, unprivileged service accounts
- internal BBS identities instead of personal Unix or container accounts
- stable, opaque server-generated user IDs
- centralized authentication and account-state checks
- roles and explicit capabilities
- no setuid-root or setgid BBS helper programs
- no public self-registration until a safe replacement exists
- explicit privilege separation and least-privilege permissions
- versioned, self-hosted interfaces for native clients and external tools

The complete normative architecture is documented in:

- [Security architecture - English](SECURITY_ARCHITECTURE.md)
- [Sicherheitsarchitektur - Deutsch](SICHERHEITS_ARCHITEKTUR.md)

These documents describe the intended end state. Some source paths are still
transitional and remain under active review.

## Current improvements

The first FortyTwo BBS development work includes:

- recursive file-tree importing with `mbfile treeimport`
- short command alias `mbfile ti`
- automatic creation and reuse of file groups and file areas
- preservation of directory structure during imports
- improved `FILES.BBS` parsing
- correct handling of multiline file descriptions
- support for up to 25 description lines with 48 characters each
- a file-description editor in `mbsetup`
- better use of modern terminal widths in `mbsetup`
- corrected field-width handling in setup screens
- hardened transitional `mblogin` handling
- centralized rejection of deleted and locked BBS accounts before sessions
- bounded environment-name handling in `mbsebbs`
- tested localhost Telnet access through `xinetd` and `telnetd`
- restricted OpenSSH test access with a forced BBS command
- disabled SSH forwarding and additional restricted-session features
- rootless Podman test operation with fixed service accounts
- removal of `mbuseradd` and `mbpasswd` from the normal build and install path
- installation of `mbtask` without setuid or setgid bits
- checked privilege dropping in `mbtask`
- optional disabling of raw ICMP monitoring with
  `MBSE_DISABLE_RAW_PING=1`
- reusable Telnet and SSH examples under `examples/fortytwo-access`
- reviewed buffer, bounds-checking and memory-management fixes
- testing with AddressSanitizer and UndefinedBehaviorSanitizer
- build-artifact exclusions through `.gitignore`

## Original MBSE features

The underlying MBSE BBS system provides, among other things:

- Fidonet support
- built-in mail tosser and front-end mailer
- TIC processing
- Areafix and Filefix
- JAM message bases
- DOS and native Linux doors
- QWK and Blue Wave offline mail
- newsgroup and email hosting or gating
- file areas and file searching
- FTP and web integration

## Building and installation

FortyTwo BBS currently retains substantial parts of the original MBSE build
and installation system.

The historical installation procedure must not be used unreviewed on a
production system. In particular, historical setuid helpers and personal
operating-system accounts for BBS users are not part of the intended
FortyTwo BBS architecture.

The original installation documentation should currently be treated only as
historical and transitional reference. Updated FortyTwo-specific installation
and migration documentation is still being developed.

## Development

The main development branch is `main`.

The original MBSE SourceForge repository remains the historical upstream
source. New FortyTwo BBS development is maintained on GitHub.

## Heritage

FortyTwo BBS is derived from MBSE BBS, originally created by
**Michiel Broek** and later maintained by the MBSE Development Team.

The original author explicitly permitted further development under the
project's GPL license, provided modified versions are clearly identified.

FortyTwo BBS is therefore presented as a modified and independently
maintained continuation, not as an official MBSE release.

## License

FortyTwo BBS is free software distributed under the
**GNU General Public License version 2**.

See the `COPYING` file for the complete license text.

## For Developers

### Current status

Public programming interfaces, extension points and compatibility guarantees
are still being designed and reviewed. Internal structures may change before
the first public release.

Undocumented functions, binary records, database layouts and internal file
formats must be considered unstable.

Direct access to historical binary files such as `users.data` is not an
intended public interface. New clients, administration tools and extensions
must not modify internal records or reimplement authentication logic.

### Architecture rules

New interfaces and extensions must follow these principles:

- BBS users are application identities, not personal operating-system accounts
- login identifiers, display names and internal user IDs are separate concepts
- user IDs are stable, opaque and generated by the server
- authentication, account state, roles and permissions are checked centrally
- passwords are never stored in plaintext or exposed to extensions
- clients and external tools use a documented, versioned FortyTwo BBS API
- internal database tables and binary files are not public APIs
- session identity must not be trusted from environment variables, command-line
  arguments or mutable display names
- public interfaces validate input and use defined error handling
- security-relevant operations are auditable
- database changes use migrations, foreign keys and transactions

### Planned developer documentation

The planned documentation includes:

- a versioned API for clients and external tools
- authentication, sessions, roles and capabilities
- stable identifiers for users, messages, files and areas
- development of doors, clients and administration tools
- Telnet, SSH, NNTP, Fidonet and web integration
- documented import, export and migration formats
- configuration and directory structures
- separation of stable public interfaces from internal implementation
- coding standards and security requirements
- versioning, deprecation and compatibility rules
- example programs and reproducible test environments

### Before the first release

Until public interfaces have been finalized:

- treat all internal APIs and data structures as unstable
- do not assume binary compatibility between development versions
- do not use production installations or valuable data for testing
- use isolated test systems, virtual machines or rootless containers
- clearly mark experimental interfaces
- accompany proposed interface changes with tests

### Contributions

Development proposals should describe:

- the problem being solved
- the proposed public interface or data format
- security implications
- compatibility implications
- expected error handling
- tests and usage examples

## Repository

Project & Source:  https://github.com/Juergen-Coding/FortyTwoBBS

Maintainer: **Juergen-Coding**

Support: https://github.com/Juergen-Coding/FortyTwoBBS/issues
