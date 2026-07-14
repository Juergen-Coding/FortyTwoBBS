# FortyTwo BBS - Rootless- und Privilegientrennungs-Architektur

## Status

Dieses Dokument legt die verbindliche Sicherheitsarchitektur für FortyTwo BBS
fest.

Diese Regeln sind normativ. Historisches Verhalten von MBSE BBS, das diesem
Dokument widerspricht, darf nicht aktiviert, installiert oder als akzeptable
Produktionsoption behandelt werden.

## 1. Sicherheitsziel

FortyTwo BBS muss als rootloser Dienst mit klarer Privilegientrennung
betrieben werden.

Ein Netzwerkbenutzer darf über die BBS, Telnet, SSH, Registrierung oder
Passwortverwaltung niemals Container-Root-Rechte, Host-Root-Rechte oder
Zugriff auf administrative Betriebssystemfunktionen erhalten können.

## 2. Host-Grenze

Der Container muss mit rootlosem Podman betrieben werden.

Folgendes ist verboten:

- privilegierte Container
- gemeinsame PID-, Benutzer- oder Netzwerk-Namespaces mit dem Host
- Zugriff auf den Podman-Socket
- uneingeschränkte Einbindung von Home-Verzeichnissen des Hosts
- Einbindung von `/etc` des Hosts
- unnötige Linux-Capabilities
- direkte Freigabe von Testports auf externen Netzwerkschnittstellen

UID 0 im Container wird auf eine unprivilegierte untergeordnete UID des Hosts
abgebildet. Sie ist damit nicht Host-Root, bleibt aber sicherheitskritisch und
muss streng eingeschränkt werden.

## 3. Rolle von Container-Root

Container-Root ist ausschließlich für kontrollierte Start- und
Dienstverwaltungsaufgaben zulässig, darunter:

- Vorbereitung der Laufzeitverzeichnisse
- Erzeugung oder Laden der SSH-Hostschlüssel
- Start von xinetd und sshd
- Start eines Dienstes, der seine Privilegien nachweislich selbst abgibt
- kontrollierte administrative Bereitstellung von Konten oder Identitäten

Container-Root darf aus einer BBS-Benutzersitzung nicht erreichbar sein.

Container-Root darf nicht über eine allgemeine Shell, einen Telnet-Befehl,
einen SSH-Befehl, ein BBS-Door oder ein Registrierungsprogramm zugänglich
gemacht werden.

## 4. Laufzeitkonten

Lang laufende FortyTwo-BBS-Prozesse müssen nach Möglichkeit unter fest
zugeordneten unprivilegierten Dienstkonten ausgeführt werden.

Derzeit vorgesehene Rollen sind:

- `mbse` für mbtask nach der überprüften Privilegienabgabe
- `fortytwo` für interaktive BBS-Sitzungen sowie notwendige Dienst- und
  Installationsabfragen
- zusätzliche feste Dienstkonten nur für klar abgegrenzte Komponenten und
  nach ausdrücklicher Sicherheitsprüfung

Netzwerkbenutzer sind interne BBS-Identitäten. Sie dürfen keine individuellen
Unix- oder Containerkonten benötigen.

Berechtigungen müssen dem Prinzip der geringsten Rechte folgen.

Gemeinsam beschreibbare Verzeichnisse müssen ausdrücklich benannt werden.
Ausführbare Dateien und Konfigurationsvorlagen dürfen für BBS-Benutzer nicht
beschreibbar sein.

## 5. Verbot von setuid- und setgid-Helfern

FortyTwo BBS darf keine privilegierten setuid-root- oder setgid-Hilfsprogramme
installieren oder verwenden.

Keine installierte ausführbare Datei darf ein setuid- oder setgid-Bit tragen,
sofern diese Vorgabe nicht nach einer künftigen Sicherheitsprüfung ausdrücklich
geändert wird.

Insbesondere dürfen die historischen MBSE-Programme

- `mbuseradd`
- `mbpasswd`

nicht als setuid-root-Programme installiert und nicht aus einer
Netzwerkbenutzersitzung aufgerufen werden.

Ihr historischer Quellcode darf vorübergehend für Prüfung, Migration und
Neuentwicklung erhalten bleiben, darf aber nicht Teil des aktiven
Container-Laufzeitpfades sein.

## 6. Benutzerbereitstellung

BBS-Code darf folgende Dateien nicht direkt verändern:

- `/etc/passwd`
- `/etc/group`
- `/etc/shadow`
- `/etc/gshadow`

Ein BBS-Benutzer ist eine interne Anwendungsidentität mit einer vom Server
erzeugten stabilen und nicht sprechenden Benutzer-ID. Das Anlegen eines
BBS-Benutzers darf kein Unix- oder Containerkonto erzeugen.

Die administrative Bereitstellung muss:

- von nicht authentifiziertem und interaktivem Sitzungscode getrennt sein
- ausschließlich eng begrenzte Operationen anbieten
- jede Eingabe prüfen
- beliebige Befehle und Pfade ablehnen
- Datenbanktransaktionen und Integritätsbedingungen verwenden
- ein Audit-Protokoll erzeugen
- bei Fernzugriff eine Begrenzung der Aufrufrate anwenden
- niemals eine Shell oder ein Betriebssystemkonto bereitstellen
- vor der Aktivierung unabhängig geprüft werden

## 7. Registrierung

Die öffentliche Selbstregistrierung bleibt deaktiviert.

`mbnewusr` darf nicht im aktiven Laufzeitsystem installiert werden und kein
Hilfsprogramm zur Verwaltung von Betriebssystemkonten aufrufen.

Die Registrierung darf erst aktiviert werden, wenn ein Ersatzkonzept
vorhanden ist, das interne BBS-Identitäten erzeugt, die zentrale
Authentifizierung verwendet und diese Architektur erfüllt.

Bis dahin werden interne BBS-Benutzer administrativ angelegt.

## 8. Authentifizierung

SSH, Telnet, NNTP, APIs und künftige native Clients müssen dasselbe interne
Identitätssystem von FortyTwo BBS verwenden.

Persönliche Unix- oder Containerkonten dürfen keine BBS-Benutzer abbilden.

Die Authentifizierung muss verwenden:

- stabile, nicht sprechende Benutzer-IDs
- eindeutig normalisierte Anmeldekennungen
- Argon2id-Passworthashes
- optionale TOTP-Zweitfaktoren
- widerrufbare serverseitige Sitzungen
- kurzlebige, nicht sprechende Zugriffstokens für APIs und native Clients
- rotierende und widerrufbare Refresh-Tokens, die nur gehasht gespeichert werden
- allgemeine externe Fehlermeldungen ohne Preisgabe interner Details
- zentrale Prüfungen auf deaktivierte, gesperrte oder abgelaufene Konten

Die Sitzungsidentität darf nicht aus Umgebungsvariablen, Kommandozeilenargumenten
oder veränderlichen Anzeigenamen übernommen werden.

Terminal-Zugänge müssen die authentifizierte Identität über eine geprüfte
lokale IPC-Verbindung oder einen versiegelten geerbten Dateideskriptor
übergeben. Dabei wird eine kurzlebige, nur einmal verwendbare und nicht
sprechende Sitzungskennung übertragen, die an die zugehörige serverseitige
Sitzung gebunden ist.

Passwörter und Kontodatensätze müssen dauerhaft gespeichert werden und dürfen
nicht von einer flüchtigen beschreibbaren Container-Schicht abhängen.

Authentifizierungsdaten dürfen niemals im Klartext enthalten sein in:

- dem Containerfile
- Image-Schichten
- Shellskripten
- Git-Commits
- öffentlichen Konfigurationsdateien

## 9. SSH-Einschränkungen

Der SSH-Zugang muss auf die FortyTwo-BBS-Anwendung beschränkt bleiben.

Erforderliche Schutzmaßnahmen sind:

- keine Root-Anmeldung
- keine beliebige entfernte Befehlsausführung
- kein Shell-Zugang für BBS-Benutzer
- kein Agent-Forwarding
- kein TCP-Forwarding
- kein X11-Forwarding
- keine Tunnel
- keine benutzerdefinierten Umgebungsvariablen
- keine benutzerdefinierten Startskripte
- ein erzwungener FortyTwo-BBS-Befehl
- eine begrenzte Anzahl gleichzeitiger Sitzungen

Kompatible Hostschlüssel dürfen bei Bedarf bereitgestellt werden. Veraltete
SSH-Algorithmen dürfen jedoch nicht ohne dokumentierte Kompatibilitäts- und
Risikoprüfung aktiviert werden.

## 10. Telnet-Einschränkungen

Telnet ist ein Kompatibilitätsdienst für die Anwendung und bietet keine
Transportverschlüsselung.

Während der Testphase muss Telnet an die Loopback-Schnittstelle gebunden
bleiben.

Eine spätere externe Telnet-Freigabe erfordert eine gesonderte dokumentierte
Entscheidung, eine Firewall-Konfiguration und einen Risikohinweis.

Telnet darf ausschließlich den geprüften BBS-Anmeldepfad starten und kein
normales System-Login oder eine Shell bereitstellen.

## 11. Eigentümer und Rechte ausführbarer Dateien

Installierte Programme und Wrapper dürfen für BBS-Benutzer nicht beschreibbar
sein.

Normale ausführbare Dateien sollten folgende Eigentümer und Rechte besitzen:

    root:root 0755

Ausschließlich administrativ verwendete Programme sollten normalerweise
folgende Eigentümer und Rechte besitzen:

    root:root 0700

Gruppenbeschreibbare ausführbare Dateien sind verboten.

Quell- und Build-Dateien dürfen dem Entwicklungskonto gehören. In das Image
kopierte Laufzeitdateien müssen jedoch kontrollierte Eigentümer und
Berechtigungen erhalten.

## 12. Capabilities und Netzwerkzugriff

Der Container darf `CAP_NET_RAW` nicht erhalten.

Die Raw-ICMP-Überwachung bleibt deaktiviert durch:

    MBSE_DISABLE_RAW_PING=1

Weitere Capabilities dürfen nur hinzugefügt werden, wenn ein dokumentierter
technischer Bedarf besteht und keine sicherere Lösung verfügbar ist.

## 13. Dauerhafte Daten

Dauerhafte Daten müssen ausdrücklich von unveränderlichen
Anwendungsbestandteilen getrennt werden.

Als Zielsystem für Identitäten und Authentifizierung wird SQLite verwendet.

Das Datenbankschema muss versionierte Migrationen, aktivierte
Fremdschlüsselbedingungen und ausdrückliche Transaktionen verwenden. Das
geplante Datenmodell umfasst mindestens:

- Benutzer
- Anmeldekennungen
- Passwort-Zugangsdaten
- Rollen und Benutzer-Rollen-Zuordnungen
- Sitzungen
- Audit-Ereignisse
- Zuordnungen des Benutzerspeichers

Die Planung der dauerhaften Speicherung muss mindestens abdecken:

- BBS-Benutzerdaten
- Nachrichten- und Dateidatenbanken
- Konfigurationsdaten
- Protokolle, die eine Neuerstellung des Containers überstehen müssen
- Konto- und Passwortdaten
- SSH-Hostschlüssel

Das vollständige BBS-Verzeichnis des Hosts darf nicht ohne eine
datei- und verzeichnisweise Prüfung der Berechtigungen in den Container
eingebunden werden.

## 14. Umgang mit Altcode

FortyTwo BBS übernimmt sicherheitskritischen Code aus MBSE BBS.

Historischer Code gilt nicht automatisch als vertrauenswürdig, nur weil er
Bestandteil der ursprünglichen Installation war.

Alter privilegierter Code muss einer der folgenden Kategorien zugeordnet
werden:

1. entfernt
2. aus dem Laufzeit-Image ausgeschlossen
3. ohne erhöhte Rechte neu geschrieben
4. hinter einer geprüften administrativen Schnittstelle isoliert

„Vom ursprünglichen Installer verwendet“ ist keine Sicherheitsbegründung.

## 15. Build- und Prüfkriterien

Bevor ein Container-Image akzeptiert wird, muss das Projekt prüfen, dass:

- keine ausführbare Datei unerwartete setuid- oder setgid-Bits besitzt
- keine ausführbare Laufzeitdatei gruppenbeschreibbar ist
- verbotene historische Hilfsprogramme fehlen oder nicht erreichbar sind
- der Container rootlos betrieben wird
- keine verbotenen Capabilities vorhanden sind
- die Einschränkungen des erzwungenen SSH-Befehls funktionieren
- beliebige SSH-Befehle abgelehnt werden
- Telnet und SSH ausschließlich die BBS starten
- Code zur Privilegienabgabe jeden Rückgabewert prüft
- dauerhafte Datenpfade ausdrücklich dokumentiert sind

## 16. Aktuelle Entscheidung

Das aktuelle FortyTwo-BBS-Konzept verwendet:

- rootloses Podman
- keinen privilegierten Modus
- keine setuid-root- oder setgid-BBS-Hilfsprogramme
- keine persönlichen Unix- oder Containerkonten für BBS-Benutzer
- interne BBS-Identitäten mit stabilen, nicht sprechenden Benutzer-IDs
- SQLite mit versionierten Migrationen, Fremdschlüsseln und Transaktionen
- kurzlebige Zugriffstokens und rotierende, gehashte Refresh-Tokens
- authentifizierte und nur einmal verwendbare lokale Sitzungsübergabe
- feste unprivilegierte Dienstkonten
- keine öffentliche Selbstregistrierung
- kontrollierte administrative Bereitstellung interner BBS-Benutzer
- unprivilegierte Laufzeitsitzungen
