# FortyTwo BBS – Architekturstand

## Dokumentstatus

- Dokumentklasse: aktueller Implementierungsstand
- Normativ: nein
- Aktueller Meilenstein: B5.1.8
- Ausgangs-Commit: `4dee601e38896f11aaf960bb7ce6a70720eff07b`
- Zuletzt geprüft: 2026-07-18

Diese Datei dokumentiert den aktuell implementierten Stand.

Die normativen Dokumente `SECURITY_ARCHITECTURE.md` und
`SICHERHEITS_ARCHITEKTUR.md` definieren die zulässige Architektur und haben
Vorrang vor dieser Datei. Ein Widerspruch ist ein Befund, der behoben werden
muss; er begründet keine alternative architektonische Wahrheit.

## Identität und führende Datenhaltung

- PostgreSQL 17 oder neuer ist die führende Instanz für Identitäten,
  Zugangsdaten, Kontozustände, Rollen, Fähigkeiten, Terminalsitzungen und
  Audit-Ereignisse.
- `users.data` und andere historische MBSE-Flatfiles sind lediglich
  vorübergehende Legacy-Kompatibilitätsdaten.
- Legacy-Dateien sind keine gleichberechtigte Quelle für Identitätsdaten.
- Neuer Code darf keine zusätzliche direkte Identitätsautorität über
  Flatfiles einführen.
- Änderungen an PostgreSQL erfolgen über versionierte und mit Prüfsummen
  versehene Migrationen.

## Authentifizierungsdienst

- `fortytwo-auth` ist derzeit ein gekapseltes Teilprojekt mit eigenen Build-
  und Testzielen.
- `fortytwo-authd` ist das geprüfte Gateway zur PostgreSQL-Identitätsdatenbank.
- FTAP 1.3 ist das versionierte lokale Authentifizierungs- und
  Registrierungsprotokoll.
- `fortytwo-auth` ist noch nicht in den historischen Top-Level-Build
  integriert.
- `fortytwo-auth` wird durch das historische Installationsverfahren nicht
  automatisch installiert.
- Ein öffentlicher, reproduzierbarer und unterstützter FortyTwo-BBS-
  Laufzeit-Build ist noch nicht freigegeben.

## Laufzeit und Vertrauensgrenzen

- Rootless Podman ist das vorgeschriebene Containermodell.
- Der aktuelle Container ist eine Entwicklungs- und Testumgebung und keine
  veröffentlichte Produktionslaufzeit.
- Netzwerkbenutzer sind interne BBS-Identitäten und keine persönlichen Unix-
  oder Containerkonten.
- Für Laufzeitkomponenten werden feste, unprivilegierte Dienstkonten
  verwendet.
- Container-root ist auf kontrollierte Bootstrap- und
  Dienstverwaltungsaufgaben beschränkt.
- BBS-Sitzungen dürfen keinen Zugriff auf eine Shell oder
  Container-root-Berechtigungen ermöglichen.
- Telnet bleibt ein Kompatibilitätstransport und ist für Tests auf die
  Loopback-Schnittstelle beschränkt.
- SSH ist durch einen erzwungenen BBS-Befehl eingeschränkt und darf weder
  beliebige Befehlsausführung noch Weiterleitungen oder eine allgemeine Shell
  ermöglichen.

## Privilegierte Legacy-Programme

- Setuid- und Setgid-Dateien sind in der Laufzeitumgebung verboten.
- `mbuseradd`, `mbpasswd` und der historische `mbnewusr`-Pfad sind keine
  freigegebenen Laufzeitkomponenten.
- Historischer privilegierter Quellcode darf für Audit- und
  Migrationsanalysen erhalten bleiben, darf jedoch nicht Teil des aktiven
  Laufzeitpfads werden.
- Laufzeitprogramme dürfen weder für BBS-Benutzer noch für Dienstkonten
  schreibbar sein.

## Aktueller Stand der Legacy-Migration

- Der Katalog der Legacy-Datendateien wurde begonnen.
- Die Datensatznummern-Semantik von `users.data` und die JAM-Bindung wurden
  analysiert.
- Eine schreibgeschützte Audit-Bestandsaufnahme von `users.data` und ein
  strikter Parser für Registrierungsmarker sind vorhanden.
- Der Abgleich zwischen PostgreSQL und Legacy-Daten ist noch nicht
  abgeschlossen.
- Verbleibende direkte Zugriffe auf `users.data` müssen identifiziert,
  dokumentiert und über kontrollierte Gateway- und Abgleichspfade migriert
  werden.
- Die NNTP-Authentifizierung und verbleibende Klartext-Passwortpfade benötigen
  weiterhin eine eigene Prüfung.

## Build- und Installationsstand

- Der historische MBSE-Build bleibt für Kompatibilität und Analyse erhalten.
- Der historische `make install`-Pfad ist kein freigegebenes
  Installationsverfahren für eine FortyTwo-BBS-Laufzeitumgebung.
- Für `fortytwo-auth` existiert noch keine freigegebene Top-Level-
  Orchestrierung.
- Es existiert noch kein endgültiger, auf einer Positivliste basierender
  Vertrag für einen öffentlichen, reproduzierbaren Laufzeit-Build und dessen
  Installation.
- Es wurde noch keine öffentliche Produktionsversion freigegeben.
- Das Repository befindet sich weiterhin im Pre-Alpha-Stadium und ist nur für
  isolierte Tests geeignet.

## Registrierungsstand

- FTAP-Registrierungsnachrichten und Schemaüberprüfungen sind vorhanden.
- Die Registrierungskomponenten befinden sich weiterhin in Entwicklung und
  Test.
- Eine öffentliche Selbstregistrierung für den Produktionsbetrieb ist noch
  nicht freigegeben.
- Die Registrierung muss interne, PostgreSQL-gestützte BBS-Identitäten
  erzeugen und darf keine Betriebssystemkonten anlegen.

## Noch nicht erreicht

- vollständiger Abgleich zwischen PostgreSQL und Legacy-Datensätzen
- Entfernung oder Kapselung jedes direkten identitätsbezogenen
  Flatfile-Zugriffs
- freigegebene Top-Level-Build-Orchestrierung
- freigegebener, auf einer Positivliste basierender Vertrag für öffentlichen
  Laufzeit-Build und Installation
- veröffentlichungsreife Container-Paketierung
- Produktionsfreigabe für Telnet, SSH oder öffentliche Registrierung
- vollständiger Ersatz der verbleibenden Legacy-Authentifizierungspfade
- endgültige externe Client-API und stabile öffentliche
  Erweiterungsschnittstellen

## Dokumenthierarchie

1. Normative Sicherheits- und Architekturdokumente
2. Protokoll-, Schema-, Migrations-, Build- und Installationsverträge
3. Dieses Dokument zum aktuellen Implementierungsstand
4. Eingefrorene Phasenberichte
5. Übergaben und Arbeitsjournale

Phasenberichte dokumentieren die Historie. Normative Dokumente und dieses
Dokument zum aktuellen Stand müssen mit dem lebenden Projekt übereinstimmen.
