
<!-- B4.3.3 STATUS START -->
## Aktueller Entwicklungsstand: B4.3.3 Telnet-Registrierung

Der aktuelle Entwicklungszweig enthält:

- PostgreSQL als führende Verwaltung für BBS-Identitäten, Zugangsdaten,
  Kontozustände, Rollen, Berechtigungen und Terminalsitzungen
- FTAP 1.3 für Anmeldung und Registrierung über einen lokalen Unix-Socket
- geschützte Telnet-Selbstregistrierung durch Eingabe von `NEW`
- einen Telnet-spezifischen Doppel-ESC-Präsenztest mit 15 Sekunden Frist
- ein optionales ASCII-, ANSI- oder CP437-Loginbild aus
  `$MBSE_ROOT/etc/issue`
- eine reine ASCII-Zahlenreihen-Aufgabe mit drei Versuchen und insgesamt
  180 Sekunden Antwortzeit
- Eingabebearbeitung mit Ctrl-H und DEL als Rücktaste
- Passwortkorrektur ohne Wiederholung einer bereits gelösten Aufgabe
- mindestens 12 Byte Passwortlänge bei der Registrierung
- kontrollierte Legacy-Anlage in `users.data` ohne Klartextpasswort
- sichere Verarbeitung einteiliger Anzeigenamen in `mbsebbs`
- korrigierte Datumseingabe ohne Schreibzugriff vor den Eingabepuffer

Die Registrierung ist standardmäßig abgeschaltet und muss sowohl in
`fortytwo-authd` als auch in `fortytwo-login` ausdrücklich freigegeben werden.
PostgreSQL bleibt führend; `users.data` wird nur vorübergehend als
Legacy-Kompatibilitätsbestand gepflegt.

<!-- B4.3.3 STATUS END -->

```text
___________            __          ___________               ____________________  _________
\_   _____/___________/  |_ ___.__.\__    ___/_  _  ______   \______   \______   \/   _____/
 |    __)/  _ \_  __ \   __<   |  |  |    |  \ \/ \/ /  _ \   |    |  _/|    |  _/\_____  \
 |     \(  <_> )  | \/|  |  \___  |  |    |   \     (  <_> )  |    |   \|    |   \/        \
 \___  / \____/|__|   |__|  / ____|  |____|    \/\_/ \____/   |______  /|______  /_______  /
     \/                     \/                                       \/        \/        \/
```

[English version](README.md)

> [!CAUTION]
> ## Entwicklungsstand: Pre-Alpha - ausschließlich für Testzwecke
>
> FortyTwo BBS wird derzeit umfassend modernisiert, sicherheitstechnisch
> überprüft und getestet.
>
> Dieses Repository ist nicht für den produktiven Einsatz, den Betrieb einer
> öffentlich erreichbaren BBS oder die Verwendung auf Produktivsystemen
> beziehungsweise produktiv eingesetzter Hardware vorgesehen.
>
> Installiere oder betreibe diese Software nicht auf Systemen, die wertvolle,
> einmalige, personenbezogene, geschäftskritische oder anderweitig nicht
> ersetzbare Daten enthalten. Verwende sie ausschließlich in einer isolierten
> Testumgebung, vorzugsweise auf einem eigenen Testrechner, in einer virtuellen
> Maschine oder in einem Rootless-Container. Halte aktuelle und unabhängig
> gespeicherte Sicherungskopien aller betroffenen Daten und Konfigurationen vor.
>
> Vor der Nutzung bist du selbst dafür verantwortlich, eine eigene
> Risikobewertung durchzuführen, geeignete technische und organisatorische
> Schutzmaßnahmen festzulegen und zu entscheiden, ob die Software für die
> vorgesehene Umgebung geeignet ist. Die Nutzung erfolgt auf eigenes Risiko.
>
> Die Software kann Abstürze, Speicherfehler, Sicherheitslücken, unvollständige
> Migrationen, inkompatible Konfigurationsänderungen und andere Fehler
> enthalten. Sie wird ohne Zusicherung hinsichtlich Funktionsfähigkeit,
> Verfügbarkeit, Kompatibilität, Sicherheit oder Eignung für einen bestimmten
> Zweck bereitgestellt.
>
> Soweit gesetzlich zulässig, übernehmen die Autoren und Mitwirkenden keine
> Haftung für Datenverlust, Datenbeschädigung, Nutzungsausfall, Systemausfälle,
> Sicherheitsvorfälle, Betriebsunterbrechungen, entgangenen Gewinn oder Kosten
> der Datenrettung, Wiederherstellung, Rekonstruktion, Neuinstallation oder
> Ersatzbeschaffung.
>
> Diese Erklärung schließt eine Haftung nicht aus und beschränkt sie nicht,
> soweit ein Ausschluss oder eine Beschränkung nach dem anwendbaren Recht
> unzulässig ist. Dies gilt insbesondere für Vorsatz, grobe Fahrlässigkeit
> sowie Schäden an Leben, Körper oder Gesundheit.
>
> Dieser Hinweis ergänzt die Bedingungen der anwendbaren
> Open-Source-Lizenz, ersetzt sie jedoch nicht.
>
> Eine erste öffentliche Testversion ist derzeit für Ende 2026 geplant.

---

**FortyTwo BBS** ist eine moderne Fortführung von **MBSE BBS**, einem in C
geschriebenen quelloffenen Bulletin-Board-System für Linux und BSD.

Das Projekt basiert auf **MBSE BBS 1.1.7.2**. Die umfangreichen Funktionen
für Fidonet, Dateibereiche, Nachrichten und Doors sollen erhalten bleiben,
während Portabilität, Sicherheit, Administration und Bedienbarkeit
schrittweise verbessert werden.

> Die Antwort mag 42 sein. Die BBS braucht trotzdem noch einen Sysop.

## Projektstatus

FortyTwo BBS befindet sich derzeit in einer frühen Entwicklungs- und
Code-Review-Phase.

Der bestehende MBSE-Quellcode wird schrittweise getestet, dokumentiert und
modernisiert. Die Kompatibilität mit bestehenden MBSE-Installationen und
Datenformaten bleibt dabei ein wichtiges Ziel.

Interne Programmnamen, Pfade und Konfigurationsstrukturen können weiterhin
die ursprüngliche Bezeichnung `mbse` verwenden.

Die aktuelle Implementierung enthält noch übergangsweise geerbten Code für
Authentifizierung und Identitätsverwaltung. Dieser Code wird schrittweise
eingegrenzt und ersetzt. Er darf nicht mit dem endgültigen
Sicherheitsmodell von FortyTwo BBS verwechselt werden.

## Sicherheitsarchitektur

Die Zielarchitektur verwendet:

- Rootless-Podman
- feste, unprivilegierte Dienstkonten
- interne BBS-Identitäten statt persönlicher Unix- oder Containerkonten
- stabile, nicht sprechende und serverseitig erzeugte Benutzer-IDs
- zentrale Authentifizierung und Prüfung des Kontostatus
- Rollen und ausdrücklich zugewiesene Berechtigungen
- keine BBS-Hilfsprogramme mit setuid-root oder setgid
- keine öffentliche Selbstregistrierung vor einem sicheren Ersatz
- klare Privilegientrennung und möglichst geringe Berechtigungen
- versionierte, selbst gehostete Schnittstellen für Clients und Werkzeuge

Die vollständige verbindliche Architektur ist dokumentiert in:

- [Sicherheitsarchitektur - Deutsch](SICHERHEITS_ARCHITEKTUR.md)
- [Security architecture - Englisch](SECURITY_ARCHITECTURE.md)

Diese Dokumente beschreiben den vorgesehenen Endzustand. Einige Bereiche des
Quellcodes sind noch Übergangslösungen und werden weiterhin überprüft.

## Aktuelle Verbesserungen

Die ersten Entwicklungsarbeiten an FortyTwo BBS umfassen:

- rekursiven Verzeichnisimport mit `mbfile treeimport`
- den kurzen Befehlsnamen `mbfile ti`
- automatische Anlage und Wiederverwendung von Datei-Gruppen und -Bereichen
- Erhaltung der Verzeichnisstruktur beim Import
- verbesserte Verarbeitung von `FILES.BBS`
- korrekte Verarbeitung mehrzeiliger Dateibeschreibungen
- bis zu 25 Beschreibungszeilen mit jeweils 48 Zeichen
- einen Editor für Dateibeschreibungen in `mbsetup`
- bessere Nutzung moderner Terminalbreiten in `mbsetup`
- korrigierte Feldbreiten in Einrichtungsdialogen
- abgesicherte übergangsweise Verarbeitung in `mblogin`
- zentrale Ablehnung gelöschter und gesperrter BBS-Konten vor Sitzungsbeginn
- begrenzte Verarbeitung von Umgebungsnamen in `mbsebbs`
- getesteten lokalen Telnet-Zugang über `xinetd` und `telnetd`
- eingeschränkten OpenSSH-Testzugang mit erzwungenem BBS-Start
- abgeschaltete SSH-Weiterleitungen und weitere Sitzungseinschränkungen
- Rootless-Podman-Testbetrieb mit festen Dienstkonten
- Entfernung von `mbuseradd` und `mbpasswd` aus dem normalen Bau- und
  Installationsweg
- Installation von `mbtask` ohne setuid- oder setgid-Bits
- überprüfte Privilegienabgabe in `mbtask`
- optionales Abschalten der RAW-ICMP-Prüfung mit
  `MBSE_DISABLE_RAW_PING=1`
- wiederverwendbare Telnet- und SSH-Beispiele unter
  `examples/fortytwo-access`
- überprüfte Korrekturen an Puffern, Bereichsprüfungen und Speicherverwaltung
- Tests mit AddressSanitizer und UndefinedBehaviorSanitizer
- Ausschluss von Bauartefakten über `.gitignore`

## Ursprüngliche MBSE-Funktionen

Das zugrunde liegende MBSE-BBS-System bietet unter anderem:

- Fidonet-Unterstützung
- eingebauten Mail-Tosser und Frontend-Mailer
- TIC-Verarbeitung
- Areafix und Filefix
- JAM-Nachrichtenbasen
- DOS-Doors und native Linux-Doors
- QWK- und Blue-Wave-Offline-Mail
- Newsgroup- und E-Mail-Hosting beziehungsweise Gateways
- Dateibereiche und Dateisuche
- FTP- und Web-Anbindung

## Bau und Installation

FortyTwo BBS verwendet derzeit noch wesentliche Teile des ursprünglichen
Bau- und Installationssystems von MBSE.

Die historische Installationsanleitung darf nicht ungeprüft auf einem
Produktivsystem verwendet werden. Insbesondere gehören historische
setuid-Hilfsprogramme und persönliche Betriebssystemkonten für BBS-Benutzer
nicht zur vorgesehenen FortyTwo-BBS-Architektur.

Die ursprüngliche Installationsdokumentation ist derzeit ausschließlich als
historische und vorläufige Referenz zu betrachten. Eine aktualisierte
FortyTwo-spezifische Installations- und Migrationsdokumentation wird noch
erstellt.

## Entwicklung

Der Hauptentwicklungszweig ist `main`.

Das ursprüngliche MBSE-Repository auf SourceForge bleibt die historische
Quelle. Die neue Entwicklung von FortyTwo BBS wird auf GitHub gepflegt.

## Herkunft

FortyTwo BBS basiert auf MBSE BBS, das ursprünglich von
**Michiel Broek** entwickelt und später vom MBSE Development Team gepflegt
wurde.

Der ursprüngliche Autor hat die Weiterentwicklung unter der GPL ausdrücklich
gestattet, sofern veränderte Fassungen klar als solche gekennzeichnet werden.

FortyTwo BBS wird daher als veränderte und unabhängig gepflegte Fortführung
veröffentlicht und nicht als offizielle MBSE-Version.

## Lizenz

FortyTwo BBS ist freie Software unter der
**GNU General Public License Version 2**.

Der vollständige Lizenztext befindet sich in der Datei `COPYING`.

## Für Entwickler

### Aktueller Stand

Die öffentlichen Programmierschnittstellen, Erweiterungspunkte und
Kompatibilitätszusagen werden noch entworfen und überprüft. Interne
Strukturen können sich bis zur ersten öffentlichen Veröffentlichung ändern.

Undokumentierte Funktionen, binäre Datensätze, Datenbankaufbauten und interne
Dateiformate sind als instabil zu behandeln.

Der direkte Zugriff auf historische Binärdateien wie `users.data` ist keine
vorgesehene öffentliche Schnittstelle. Neue Clients,
Administrationswerkzeuge und Erweiterungen dürfen interne Datensätze nicht
verändern und keine eigene Authentifizierungslogik nachbilden.

### Architekturregeln

Für neue Schnittstellen und Erweiterungen gelten folgende Grundsätze:

- BBS-Benutzer sind Anwendungsidentitäten und keine persönlichen
  Betriebssystemkonten
- Anmeldekennung, Anzeigename und interne Benutzer-ID sind getrennte Begriffe
- Benutzer-IDs werden vom Server erzeugt, sind stabil und nicht sprechend
- Authentifizierung, Kontostatus, Rollen und Berechtigungen werden zentral
  geprüft
- Passwörter werden weder im Klartext gespeichert noch an Erweiterungen
  weitergegeben
- Clients und externe Werkzeuge verwenden eine dokumentierte, versionierte
  FortyTwo-BBS-API
- interne Datenbanktabellen und Binärdateien sind keine öffentlichen APIs
- Sitzungsidentitäten dürfen nicht aus Umgebungsvariablen,
  Kommandozeilenargumenten oder veränderlichen Anzeigenamen vertraut werden
- öffentliche Schnittstellen prüfen ihre Eingaben und verwenden definierte
  Fehlerbehandlung
- sicherheitsrelevante Vorgänge müssen nachvollziehbar protokolliert werden
- Datenbankänderungen verwenden Migrationen, Fremdschlüssel und Transaktionen

### Geplante Entwicklerdokumentation

Die geplante Dokumentation umfasst:

- eine versionierte API für Clients und externe Werkzeuge
- Authentifizierung, Sitzungen, Rollen und Berechtigungen
- stabile Kennungen für Benutzer, Nachrichten, Dateien und Bereiche
- Entwicklung von Doors, Clients und Administrationswerkzeugen
- Telnet-, SSH-, NNTP-, Fidonet- und Web-Anbindung
- dokumentierte Import-, Export- und Migrationsformate
- Verzeichnisstruktur und Konfigurationsdateien
- Trennung stabiler öffentlicher Schnittstellen von interner Implementierung
- Coding-Standards und Sicherheitsanforderungen
- Regeln für Versionierung, Abkündigung und Abwärtskompatibilität
- Beispielprogramme und reproduzierbare Testumgebungen

### Vor der ersten Veröffentlichung

Bis die öffentlichen Schnittstellen festgelegt wurden, gilt:

- alle internen APIs und Datenstrukturen als instabil behandeln
- keine Binärkompatibilität zwischen Entwicklungsversionen voraussetzen
- keine Produktivinstallationen oder wertvollen Daten für Tests verwenden
- isolierte Testsysteme, virtuelle Maschinen oder Rootless-Container nutzen
- experimentelle Schnittstellen eindeutig kennzeichnen
- vorgeschlagene Schnittstellenänderungen mit Tests versehen

### Mitwirkung

Entwicklungsvorschläge sollten Folgendes beschreiben:

- das zu lösende Problem
- die vorgeschlagene öffentliche Schnittstelle oder das Datenformat
- Auswirkungen auf die Sicherheit
- Auswirkungen auf die Kompatibilität
- erwartete Fehlerbehandlung
- Tests und Anwendungsbeispiele

## Repository

Projekt & Betreuer: https://github.com/Juergen-Coding/

Support: https://github.com/Juergen-Coding/FortyTwoBBS/issues
