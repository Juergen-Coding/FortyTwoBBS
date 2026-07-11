```text
___________            __          ___________               ____________________  _________
\_   _____/___________/  |_ ___.__.\__    ___/_  _  ______   \______   \______   \/   _____/
 |    __)/  _ \_  __ \   __<   |  |  |    |  \ \/ \/ /  _ \   |    |  _/|    |  _/\_____  \ 
 |     \(  <_> )  | \/|  |  \___  |  |    |   \     (  <_> )  |    |   \|    |   \/        \
 \___  / \____/|__|   |__|  / ____|  |____|    \/\_/ \____/   |______  /|______  /_______  /
     \/                     \/                                       \/        \/        \/ 
```

> [!CAUTION]
> ## Development status: Pre-alpha - testing only
>
> FortyTwo BBS is currently undergoing extensive modernization, security review and testing.
>
> This repository is not intended for production use, the operation of a publicly accessible BBS, or use on production systems or production hardware.
>
> Do not install or run this software on systems that contain valuable, unique, personal, business-critical or otherwise irreplaceable data. Use it only in an isolated test environment, preferably on a dedicated test machine or virtual machine, and maintain current, independently stored backups of all affected data and configurations.
>
> Before using the software, you are responsible for carrying out your own risk assessment, determining appropriate technical and organizational safeguards, and deciding whether the software is suitable for the intended environment. Use of the software is entirely at your own risk.
>
> The software may contain crashes, memory errors, security vulnerabilities, incomplete migrations, incompatible configuration changes and other defects. It is provided without any guarantee of functionality, availability, compatibility, security or fitness for a particular purpose.
>
> To the maximum extent permitted by applicable law, the authors and contributors accept no liability for data loss, data corruption, loss of use, system failure, security incidents, business interruption, loss of profits, or any costs arising from recovery, restoration, reconstruction, reinstallation or replacement procurement.
>
> Nothing in this notice excludes or limits liability where such exclusion or limitation is prohibited by applicable law, including liability for intentional misconduct, gross negligence, or injury to life, body or health.
>
> This notice supplements, but does not replace, the terms of the applicable open-source license.
>
> A first public test release is currently planned for late 2026.

---

> [!CAUTION]
> ## Entwicklungsstand: Pre-Alpha - ausschließlich für Testzwecke
>
> FortyTwo BBS wird derzeit umfassend modernisiert, sicherheitstechnisch überprüft und getestet.
>
> Dieses Repository ist nicht für den produktiven Einsatz, den Betrieb einer öffentlich erreichbaren BBS oder die Verwendung auf Produktivsystemen beziehungsweise produktiv eingesetzter Hardware vorgesehen.
>
> Installiere oder betreibe diese Software nicht auf Systemen, die wertvolle, einmalige, personenbezogene, geschäftskritische oder anderweitig nicht ersetzbare Daten enthalten. Verwende sie ausschließlich in einer isolierten Testumgebung, vorzugsweise auf einem eigenen Testrechner oder in einer virtuellen Maschine. Halte aktuelle und unabhängig gespeicherte Sicherungskopien aller betroffenen Daten und Konfigurationen vor.
>
> Vor der Nutzung bist du selbst dafür verantwortlich, eine eigene Risikobewertung durchzuführen, geeignete technische und organisatorische Schutzmaßnahmen festzulegen und zu entscheiden, ob die Software für die vorgesehene Umgebung geeignet ist. Die Nutzung erfolgt auf eigenes Risiko.
>
> Die Software kann Abstürze, Speicherfehler, Sicherheitslücken, unvollständige Migrationen, inkompatible Konfigurationsänderungen und andere Fehler enthalten. Sie wird ohne Zusicherung hinsichtlich Funktionsfähigkeit, Verfügbarkeit, Kompatibilität, Sicherheit oder Eignung für einen bestimmten Zweck bereitgestellt.
>
> Soweit gesetzlich zulässig, übernehmen die Autoren und Mitwirkenden keine Haftung für Datenverlust, Datenbeschädigung, Nutzungsausfall, Systemausfälle, Sicherheitsvorfälle, Betriebsunterbrechungen, entgangenen Gewinn oder Kosten der Datenrettung, Wiederherstellung, Rekonstruktion, Neuinstallation oder Ersatzbeschaffung.
>
> Diese Erklärung schließt eine Haftung nicht aus und beschränkt sie nicht, soweit ein Ausschluss oder eine Beschränkung nach dem anwendbaren Recht unzulässig ist. Dies gilt insbesondere für Vorsatz, grobe Fahrlässigkeit sowie Schäden an Leben, Körper oder Gesundheit.
>
> Dieser Hinweis ergänzt die Bedingungen der anwendbaren Open-Source-Lizenz, ersetzt sie jedoch nicht.
>
> Eine erste öffentliche Testversion ist derzeit für Ende 2026 geplant.
---
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
- modernized `mblogin` handling for FortyTwo installations and the active user database
- tested localhost Telnet access through `xinetd` and `telnetd`, including a custom login banner
- separate restricted OpenSSH access for registered BBS users, with a forced BBS command and forwarding disabled
- reusable Telnet and SSH configuration examples under `examples/fortytwo-access`
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
