# FortyTwo BBS

**FortyTwo BBS** is a modern continuation of **MBSE BBS**, an open-source Bulletin Board System written in C for Linux and BSD.

The project is based on **MBSE BBS 1.1.7.2** and preserves its extensive Fidonet, filebase, mail and door functionality while gradually improving portability, safety, administration and usability.

> The answer may be 42. The BBS still needs a sysop.

## Project status

FortyTwo BBS is currently in an early development and code-review phase.

The existing MBSE codebase is being tested, documented and modernized incrementally. Compatibility with existing MBSE installations and data formats remains an important goal.

Internal program names, paths and configuration structures may still use the original `mbse` naming.

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
- several reviewed buffer and memory-safety fixes
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

FortyTwo BBS currently retains the original MBSE build and installation system.

See the original installation documentation for the existing procedure. The installation process is still being reviewed and will receive updated FortyTwo-specific documentation.

## Development

The main development branch is `main`.

The original MBSE SourceForge repository remains the historical upstream source. New FortyTwo BBS development is maintained on GitHub.

## Heritage

FortyTwo BBS is derived from MBSE BBS, originally created by **Michiel Broek** and later maintained by the MBSE Development Team.

The original author explicitly permitted further development under the project's GPL license, provided modified versions are clearly identified.

FortyTwo BBS is therefore presented as a modified and independently maintained continuation, not as an official MBSE release.

## License

FortyTwo BBS is free software distributed under the **GNU General Public License version 2**.

See the `COPYING` file for the complete license text.

## Repository

https://github.com/Juergen-Coding/FortyTwoBBS

Maintainer: **Juergen-Coding**
