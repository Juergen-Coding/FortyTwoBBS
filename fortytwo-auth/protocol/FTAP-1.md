# FortyTwo Authentication Protocol – FTAP/1

Status: Interne Protokollspezifikation
Dokumentrevision: 1.2
Wire-Version: FTAP 1.1
Transport: lokaler Unix-Domain-Socket
Standardpfad: `/run/fortytwo/auth.sock`

Dokumentrevision 1.2 konsolidiert vor Beginn der Implementierung:

- einen eigenen Service-Modus für `fortytwo-api`,
- parallele, über Request-IDs gemultiplexte Anfragen,
- verbindliche Regeln für Server-Push-Interleaving,
- eindeutige TLV-Kardinalitäten,
- einheitliche Versionsfeldbreiten,
- explizite Werte für Protokoll und Authentifizierungsmethode,
- die bewusste Zurückstellung interner SSH-Public-Key-Anmeldung.

## 1. Zweck

FTAP verbindet lokale FortyTwo-Prozesse mit `fortytwo-authd`.

Teilnehmer sind zunächst:

- `fortytwo-login`
- `mbsebbs`
- spätere Verwaltungswerkzeuge
- später `fortytwo-api`

Nur `fortytwo-authd` greift direkt auf die Identitätsdatenbank zu.

FTAP überträgt keine PostgreSQL-Zugangsdaten oder Passwort-Hashes.

Terminal-Sitzungen verwenden keine übertragbaren Bearer-Tokens. Die spätere
HTTP-API verwendet dagegen ausdrücklich opake Access-Tokens. Diese werden nur
auf dafür autorisierten Service-Verbindungen an `fortytwo-authd` übergeben.

## 2. Vertrauensmodell

Der Unix-Socket wird durch zwei voneinander unabhängige Mechanismen geschützt:

1. Dateisystemrechte auf `/run/fortytwo` und `auth.sock`
2. Prüfung der Peer-Credentials durch `SO_PEERCRED`

Eine erfolgreiche Socket-Verbindung allein bedeutet noch keine
authentifizierte BBS-Sitzung.

Der Auth-Daemon entscheidet anhand der Peer-Credentials, welche
Nachrichtentypen ein verbundener Prozess verwenden darf.

## 3. Byte-Reihenfolge

Alle mehrbyteigen Ganzzahlen werden in Network Byte Order
beziehungsweise Big Endian übertragen.

Native C-Strukturen dürfen niemals direkt auf den Socket geschrieben werden.

## 4. Frame-Header

Jede Nachricht beginnt mit einem exakt 24 Byte langen Header:

| Offset | Länge | Feld             | Typ      |
|-------:|------:|------------------|----------|
| 0      | 4     | Magic            | Bytes    |
| 4      | 2     | Major-Version    | uint16   |
| 6      | 2     | Minor-Version    | uint16   |
| 8      | 2     | Nachrichtentyp   | uint16   |
| 10     | 2     | Flags            | uint16   |
| 12     | 4     | Payload-Länge    | uint32   |
| 16     | 8     | Request-ID       | uint64   |

### 4.1 Magic

Der Magic-Wert lautet:

```text
FTAP
```

Hexadezimal:

```text
46 54 41 50
```

### 4.2 Version

Für das Wire-Format dieser Spezifikation gilt:

```text
Major-Version: 1
Minor-Version: 1
```

Die Dokumentrevision ist davon unabhängig. Reine Klarstellungen und
Implementierungsregeln erhöhen nicht automatisch die Wire-Version.

Eine unbekannte Major-Version wird abgewiesen.

Eine höhere unbekannte Minor-Version darf nur akzeptiert werden, wenn keine
unbekannten kritischen Felder oder Flags vorkommen.

### 4.3 Payload-Länge

Die maximale Payload-Länge beträgt in FTAP/1:

```text
65536 Byte
```

Größere Frames werden abgewiesen und die Verbindung wird geschlossen.

### 4.4 Request-ID

Clientanfragen verwenden eine vom Client gewählte Request-ID größer als null.

Die Antwort übernimmt dieselbe Request-ID.

Asynchrone Servernachrichten verwenden:

```text
Request-ID = 0
```

### 4.5 Antwortzuordnung und Interleaving

Antworten werden ausschließlich anhand ihrer Request-ID einer Anfrage
zugeordnet.

Der Empfänger darf nicht voraussetzen, dass Antworten in derselben Reihenfolge
eintreffen wie Anfragen.

`SERVER_PUSH`-Nachrichten mit Request-ID `0` dürfen zwischen beliebigen
Anfragen und Antworten auftreten.

## 5. Header-Flags

| Bit | Name          | Bedeutung                         |
|----:|---------------|-----------------------------------|
| 0   | RESPONSE      | Nachricht ist eine Antwort        |
| 1   | SERVER_PUSH   | asynchrone Servernachricht        |
| 2   | ERROR         | Fehlerantwort                     |
| 3–15| reserviert    | müssen in FTAP/1 null sein         |

Unbekannte gesetzte Header-Flags führen zu `FTAP_ERR_PROTOCOL`.

## 6. Payload-Format

Die Payload besteht aus null oder mehr TLV-Feldern.

Jedes TLV-Feld besitzt einen 8 Byte langen Header:

| Offset | Länge | Feld          | Typ    |
|-------:|------:|---------------|--------|
| 0      | 2     | Feldtyp       | uint16 |
| 2      | 2     | Feld-Flags    | uint16 |
| 4      | 4     | Feldlänge     | uint32 |
| 8      | n     | Feldwert      | Bytes  |

### 6.1 Feld-Flags

| Bit | Name      | Bedeutung                                      |
|----:|-----------|------------------------------------------------|
| 0   | CRITICAL  | unbekanntes Feld muss zum Abbruch führen       |
| 1–15| reserviert| müssen in FTAP/1 null sein                      |

Unbekannte nichtkritische Felder dürfen übersprungen werden.

Unbekannte kritische Felder führen zu `FTAP_ERR_UNSUPPORTED_FIELD`.

### 6.2 Datentypen

- Text: UTF-8 ohne abschließendes Nullbyte
- UUID: 16 rohe Byte
- Boolean: exakt ein Byte, `0` oder `1`
- uint16, uint32 und uint64: Big Endian
- IP-Adresse: Text in kanonischer IPv4- oder IPv6-Darstellung
- Passwort: UTF-8-Bytefolge, maximal 1024 Byte

Texte dürfen keine eingebetteten Nullbytes enthalten.

### 6.3 Feldkardinalität und doppelte Felder

Die erlaubte Häufigkeit eines Feldtyps wird für jeden Nachrichtentyp
ausdrücklich festgelegt.

Für alle Felder gilt standardmäßig:

```text
0..1
```

Ein nicht ausdrücklich als wiederholbar markiertes Feld darf pro Nachricht
höchstens einmal vorkommen. Ein zweites Vorkommen führt zu
`FTAP_ERR_PROTOCOL`.

Es gilt niemals „erstes Feld gewinnt“ oder „letztes Feld gewinnt“.

`CAPABILITY` ist nur in ausdrücklich genannten Ergebnisnachrichten
wiederholbar. In `AUTHZ_CHECK_REQUEST` ist genau ein `CAPABILITY`-Feld erlaubt.

### 6.4 Vollständige Payload-Prüfung

Der Parser muss die deklarierte Payload exakt konsumieren.

Für jedes TLV-Feld wird vor Addition geprüft:

```text
8 + Feldlänge
```

Die Summe aller TLV-Header und Feldwerte muss exakt der im Frame-Header
deklarierten Payload-Länge entsprechen.

Nicht zulässig sind:

- Überlaufen der deklarierten Payload-Länge,
- abgeschnittene TLV-Header,
- abgeschnittene Feldwerte,
- nicht interpretierte Restbytes,
- Ganzzahlüberläufe bei Offset- oder Längenberechnungen.

## 7. Größenlimits

| Feld                         | Maximum |
|------------------------------|--------:|
| Loginname                    | 32 Byte |
| Anzeigename                  | 64 Byte |
| Capability-Name              | 96 Byte |
| Protokollname                | 16 Byte |
| Authentifizierungsmethode    | 32 Byte |
| TTY-Gerät                    | 128 Byte |
| Node-ID                      | 64 Byte |
| IP-Adresse                   | 45 Byte |
| Clientname                   | 64 Byte |
| Clientversion                | 32 Byte |
| Dienstname                   | 64 Byte |
| Fehlertext                   | 256 Byte |
| Passwort                     | 1024 Byte |
| Opakes Access-Token           | 512 Byte |

Der Empfänger prüft alle Längen vor einer Speicherreservierung oder Kopie.

## 8. Verbindungszustände

Eine FTAP-Verbindung befindet sich immer in genau einem Zustand:

```text
CONNECTED
HELLO_COMPLETE
AUTHENTICATING
SESSION_BOUND
SERVICE_BOUND
CLOSING
```

Erlaubte Übergänge:

```text
Terminalverbindung:

CONNECTED
    -> HELLO_COMPLETE
    -> AUTHENTICATING
    -> SESSION_BOUND
    -> CLOSING

Vertrauenswürdige Dienstverbindung:

CONNECTED
    -> HELLO_COMPLETE
    -> SERVICE_BOUND
    -> CLOSING
```

Ungültige Nachrichtentypen für den aktuellen Zustand führen zu
`FTAP_ERR_INVALID_STATE`.

## 9. Nachrichtentypen

### 9.1 Allgemeine Nachrichten

| Wert | Name        |
|-----:|-------------|
| 1    | HELLO                |
| 2    | HELLO_OK             |
| 3    | ERROR                |
| 4    | SERVICE_BIND_REQUEST |
| 5    | SERVICE_BIND_RESULT  |

### 9.2 Passwortanmeldung

| Wert | Name                    |
|-----:|-------------------------|
| 100  | AUTH_PASSWORD_REQUEST   |
| 101  | AUTH_PASSWORD_RESULT    |

### 9.3 Sitzungskontext

| Wert | Name                    |
|-----:|-------------------------|
| 110  | SESSION_CONTEXT_REQUEST |
| 111  | SESSION_CONTEXT_RESULT  |
| 112  | SESSION_HEARTBEAT       |
| 113  | SESSION_AUTHZ_CHANGED   |

### 9.4 Autorisierung

| Wert | Name                    |
|-----:|-------------------------|
| 120  | AUTHZ_CHECK_REQUEST     |
| 121  | AUTHZ_CHECK_RESULT      |

### 9.5 Sitzungsende und Widerruf

| Wert | Name             |
|-----:|------------------|
| 130  | SESSION_CLOSE    |
| 131  | SESSION_REVOKED  |

### 9.6 API-Token und Service-Kontext

| Wert | Name                  |
|-----:|-----------------------|
| 140  | TOKEN_CONTEXT_REQUEST |
| 141  | TOKEN_CONTEXT_RESULT  |

## 10. Feldtypen

| Wert | Name                    | Datentyp       |
|-----:|-------------------------|----------------|
| 1    | CLIENT_NAME             | Text           |
| 2    | CLIENT_VERSION          | Text           |
| 3    | SUPPORTED_MAJOR         | uint16         |
| 4    | SUPPORTED_MINOR         | uint16         |
| 5    | SERVICE_NAME            | Text           |
| 10   | LOGIN_NAME              | Text           |
| 11   | PASSWORD                | Bytes/Text     |
| 12   | PROTOCOL                | Text           |
| 13   | SOURCE_IP               | Text           |
| 14   | TTY_DEVICE              | Text           |
| 15   | NODE_ID                 | Text           |
| 16   | AUTH_METHOD             | Text           |
| 20   | USER_ID                 | UUID           |
| 21   | SESSION_ID              | UUID           |
| 22   | DISPLAY_NAME            | Text           |
| 23   | ACCOUNT_STATE           | Text           |
| 24   | AUTH_EPOCH              | uint64         |
| 25   | AUTHZ_REVISION          | uint64         |
| 26   | CAPABILITY              | Text           |
| 30   | RESOURCE_TYPE           | Text           |
| 31   | RESOURCE_ID             | Text           |
| 32   | AUTHZ_ALLOWED           | Boolean        |
| 40   | ENDED_REASON            | Text           |
| 41   | REVOKE_REASON           | Text           |
| 50   | ERROR_CODE              | uint32         |
| 51   | ERROR_TEXT              | Text           |
| 52   | RETRY_AFTER_MS          | uint32         |
| 60   | ACCESS_TOKEN            | Bytes/Text     |
| 61   | API_SESSION_ID          | UUID           |

## 11. HELLO

Nach dem Verbindungsaufbau muss der Client zuerst `HELLO` senden.

Pflichtfelder:

```text
CLIENT_NAME
CLIENT_VERSION
SUPPORTED_MAJOR
SUPPORTED_MINOR
```

`fortytwo-authd` prüft zusätzlich die Peer-Credentials.

Bei Erfolg antwortet der Server mit `HELLO_OK`.

Vor erfolgreichem `HELLO` sind keine anderen Anfragen erlaubt.

`SUPPORTED_MAJOR` und `SUPPORTED_MINOR` sind wie die Versionsfelder im
Frame-Header jeweils `uint16`.

## 12. Vertrauenswürdige Service-Verbindungen

Ein Prozess wie `fortytwo-api` bindet keine einzelne Benutzersitzung dauerhaft
an seine FTAP-Verbindung.

Nach erfolgreichem `HELLO` sendet ein dafür über Peer-Credentials
autorisierter Prozess:

```text
SERVICE_BIND_REQUEST
```

Pflichtfeld:

```text
SERVICE_NAME
```

Für die erste API-Implementierung lautet der erlaubte Wert:

```text
fortytwo-api
```

Bei Erfolg antwortet `fortytwo-authd` mit `SERVICE_BIND_RESULT`, und die
Verbindung wechselt in den Zustand `SERVICE_BOUND`.

Eine Service-Verbindung darf viele voneinander unabhängige Benutzeranfragen
über dieselbe Socket-Verbindung abwickeln.

`fortytwo-api` verwendet dafür einen kleinen Pool langlebiger
`SERVICE_BOUND`-Verbindungen. Es wird nicht für jede HTTP-Anfrage eine neue
FTAP-Verbindung aufgebaut.

### 12.1 Tokenbezug statt bloßer Sitzungskennung

Eine API-Anfrage wird nicht allein durch `SESSION_ID` oder `API_SESSION_ID`
autorisiert. Diese Werte sind Identifikatoren und keine Credentials.

Der API-Daemon übergibt das vom HTTP-Client empfangene opake `ACCESS_TOKEN` an
`fortytwo-authd`.

Nur `fortytwo-authd`:

- hasht und prüft das Token,
- prüft Ablauf, Widerruf und `auth_epoch`,
- ermittelt die zugehörige API-Sitzung und Benutzeridentität,
- trifft die Autorisierungsentscheidung.

Ein bloßes `SESSION_ID`-Feld in einer Service-Anfrage ist unzulässig und führt
zu `FTAP_ERR_PROTOCOL`.

### 12.2 Tokenkontext

`TOKEN_CONTEXT_REQUEST` ist nur im Zustand `SERVICE_BOUND` zulässig.

Pflichtfeld:

```text
ACCESS_TOKEN
```

`TOKEN_CONTEXT_RESULT` enthält bei Erfolg mindestens:

```text
USER_ID
API_SESSION_ID
LOGIN_NAME
DISPLAY_NAME
AUTH_EPOCH
AUTHZ_REVISION
```

`CAPABILITY` darf in dieser Ergebnisnachricht null- bis mehrfach vorkommen.

### 12.3 Multiplexing

Auf einer `SERVICE_BOUND`-Verbindung dürfen mehrere Clientanfragen gleichzeitig
offen sein.

Jede Anfrage besitzt eine eindeutige Request-ID größer als null.

Antworten dürfen in anderer Reihenfolge eintreffen als die Anfragen. Der Client
ordnet sie ausschließlich über die Request-ID zu.

Eine Request-ID darf auf derselben Verbindung erst wiederverwendet werden,
nachdem die vorherige Anfrage vollständig abgeschlossen oder verworfen wurde.

Empfängt `fortytwo-authd` eine Request-ID, die auf derselben Verbindung noch
als offen geführt wird, gilt dies als Protokollfehler.

Der Server darf die bestehende Anfrage niemals:

- überschreiben,
- stillschweigend verwerfen,
- mit der neuen Anfrage zusammenführen.

Soweit noch sicher möglich, sendet der Server `FTAP_ERR_PROTOCOL`. Danach
schließt er die betroffene Service-Verbindung. Alle auf dieser Verbindung noch
offenen Anfragen gelten als fehlgeschlagen und dürfen vom Client nur nach
seinen normalen Wiederholungsregeln erneut gestellt werden.

### 12.4 Verantwortungsgrenze beim Rate-Limiting

`fortytwo-api` ist gegenüber FTAP ein vertrauenswürdiger lokaler Dienst, nicht
der eigentliche entfernte Endnutzer.

Die endnutzerbezogene Begrenzung von HTTP-Anfragen erfolgt deshalb in
`fortytwo-api`, insbesondere nach:

- tatsächlicher Client-IP,
- Access-Token beziehungsweise API-Sitzung,
- HTTP-Endpunkt,
- Benutzeridentität, sobald diese sicher ermittelt wurde,
- auffälligen Fehlversuchen oder ungültigen Token.

`fortytwo-authd` prüft weiterhin jedes übergebene Access-Token verbindlich
gegen Ablauf, Widerruf und `auth_epoch`. Es übernimmt jedoch nicht automatisch
die vollständige HTTP-Abuse-Erkennung für einzelne entfernte Clients.

Zum eigenen Schutz darf `fortytwo-authd` zusätzlich defensive Grenzen
erzwingen, beispielsweise:

- maximale offene Anfragen pro Service-Verbindung,
- maximale Gesamtzahl offener Service-Anfragen,
- begrenzte interne Warteschlangen,
- Zeitlimits,
- globale oder dienstbezogene Überlastgrenzen.

Diese Schutzgrenzen ersetzen das HTTP-Rate-Limiting in `fortytwo-api` nicht.

## 13. Passwortanmeldung

`AUTH_PASSWORD_REQUEST` darf nur von dafür zugelassenen Loginprozessen
gesendet werden.

Pflichtfelder:

```text
LOGIN_NAME
PASSWORD
PROTOCOL
AUTH_METHOD
```

Für `AUTH_PASSWORD_REQUEST` sind in FTAP/1.1 ausschließlich folgende Werte
zulässig:

```text
PROTOCOL    = telnet | ssh | local
AUTH_METHOD = password
```

Andere Werte führen zu `FTAP_ERR_PROTOCOL`.

Optionale Felder:

```text
SOURCE_IP
TTY_DEVICE
NODE_ID
```

Der Auth-Daemon:

1. normalisiert den Loginnamen,
2. wendet Rate-Limits an,
3. prüft das Passwort über Argon2id,
4. prüft Kontostatus und `throttled_until`,
5. erzeugt bei Erfolg eine Terminal-Sitzung,
6. bindet diese Sitzung an die bestehende Socket-Verbindung,
7. löscht den Klartextpasswortpuffer.

Bei Erfolg enthält `AUTH_PASSWORD_RESULT` mindestens:

```text
USER_ID
SESSION_ID
LOGIN_NAME
DISPLAY_NAME
AUTH_EPOCH
AUTHZ_REVISION
```

Zusätzlich darf `CAPABILITY` mehrfach vorkommen.

Nach erfolgreicher Anmeldung wechselt die Verbindung in den Zustand
`SESSION_BOUND`.

Das Passwort wird niemals in einer Antwort zurückgesendet.

## 14. Geerbter Sitzungs-Dateideskriptor

Nach erfolgreicher Anmeldung startet `fortytwo-login` den BBS-Prozess per
`execve()`.

Die authentifizierte FTAP-Verbindung bleibt als fest definierter
Dateideskriptor geöffnet:

```text
FD 3
```

Der Dateideskriptor darf nicht mit `FD_CLOEXEC` markiert sein.

Alle anderen nicht benötigten Dateideskriptoren werden vor `execve()`
geschlossen.

Die Sitzung ist an die bestehende Socket-Verbindung gebunden. Es wird kein
übertragbares Bearer-Token erzeugt.

## 15. Sitzungskontext

Nach dem Start sendet `mbsebbs`:

```text
SESSION_CONTEXT_REQUEST
```

Es sind keine vom Client frei gewählten Benutzer- oder Sitzungskennungen
erforderlich. `fortytwo-authd` kennt die an diese Verbindung gebundene Sitzung.

Die Antwort `SESSION_CONTEXT_RESULT` enthält mindestens:

```text
USER_ID
SESSION_ID
LOGIN_NAME
DISPLAY_NAME
PROTOCOL
AUTH_METHOD
AUTH_EPOCH
AUTHZ_REVISION
```

`CAPABILITY` darf in dieser Ergebnisnachricht null- bis mehrfach vorkommen.

## 16. Autorisierungsprüfung

Für ressourcenbezogene Prüfungen sendet der Client:

```text
AUTHZ_CHECK_REQUEST
```

In jeder `AUTHZ_CHECK_REQUEST` ist genau ein `CAPABILITY`-Feld erlaubt.

Mehrere Capability-Felder sind ein Protokollfehler; es gibt keine implizite
UND- oder ODER-Semantik.

### 16.1 Sitzunggebundene Terminalverbindung

Im Zustand `SESSION_BOUND` sind Pflichtfelder:

```text
CAPABILITY
```

Optionale Felder:

```text
RESOURCE_TYPE
RESOURCE_ID
```

`ACCESS_TOKEN`, `SESSION_ID` und `API_SESSION_ID` sind in diesem Zustand
verboten. Die Identität ergibt sich ausschließlich aus der gebundenen
Socket-Sitzung.

### 16.2 Vertrauenswürdige Service-Verbindung

Im Zustand `SERVICE_BOUND` sind Pflichtfelder:

```text
ACCESS_TOKEN
CAPABILITY
```

Optionale Felder:

```text
RESOURCE_TYPE
RESOURCE_ID
```

`fortytwo-authd` validiert das Access-Token und prüft die Capability in einem
gemeinsamen Vorgang.

Ein bloßes `SESSION_ID` oder `API_SESSION_ID` ersetzt das Access-Token nicht.

Beispiel:

```text
CAPABILITY    = message.moderate
RESOURCE_TYPE = message_area
RESOURCE_ID   = 42
```

Die Antwort `AUTHZ_CHECK_RESULT` enthält:

```text
AUTHZ_ALLOWED
AUTHZ_REVISION
```

Der Client darf eine fehlende oder fehlerhafte Antwort niemals als Erlaubnis
interpretieren.

### 16.3 Server-Push und ausstehende Anfragen

Ein Client muss jederzeit mit `SERVER_PUSH`-Nachrichten mit Request-ID `0`
rechnen, auch wenn eigene Anfragen noch offen sind.

Insbesondere darf eine Leseschleife nicht voraussetzen:

```text
Die nächste empfangene Nachricht ist die Antwort auf meine letzte Anfrage.
```

`SESSION_REVOKED` hat Vorrang vor noch ausstehenden normalen Antworten. Nach
seinem Empfang darf der Client keine positive Autorisierungsantwort mehr
verwenden, selbst wenn diese bereits unterwegs war.

Terminalclients dürfen ihre eigenen Anfragen seriell senden, müssen
Server-Push-Nachrichten aber dennoch jederzeit verarbeiten können.

## 17. Berechtigungsänderungen

Ändern sich Rollen oder Capabilities einer laufenden Sitzung, sendet
`fortytwo-authd` asynchron:

```text
SESSION_AUTHZ_CHANGED
```

Header:

```text
SERVER_PUSH = 1
Request-ID  = 0
```

Enthalten ist mindestens:

```text
AUTHZ_REVISION
```

Der Client verwirft daraufhin seinen bisherigen Capability-Snapshot und
fordert den Sitzungskontext neu an.

## 18. Sitzungswiderruf

Bei Sperrung, Deaktivierung, Passwortänderung oder administrativer Abmeldung
sendet `fortytwo-authd`:

```text
SESSION_REVOKED
```

Header:

```text
SERVER_PUSH = 1
Request-ID  = 0
```

Pflichtfeld:

```text
REVOKE_REASON
```

Der Client:

1. beendet laufende sicherheitsrelevante Aktionen,
2. zeigt soweit möglich eine neutrale Meldung,
3. sendet optional `SESSION_CLOSE`,
4. beendet den BBS-Prozess.

Ein widerrufener Client darf keine weiteren normalen Anfragen senden.

## 19. Heartbeat

Aktive Terminalprozesse dürfen regelmäßig `SESSION_HEARTBEAT` senden.

Der Auth-Daemon aktualisiert damit `last_seen_at`.

Ein Heartbeat enthält keine frei gewählte Benutzeridentität.

Das genaue Intervall wird später konfigurierbar festgelegt.

## 20. Geordnetes Sitzungsende

Beim normalen Logout sendet der Client:

```text
SESSION_CLOSE
```

Optionales Feld:

```text
ENDED_REASON
```

Danach wird die Verbindung geschlossen.

Bei unerwartetem Socketabbruch markiert `fortytwo-authd` die Sitzung mit einem
geeigneten Beendigungsgrund als geschlossen.

## 21. Fehlercodes

| Wert | Name                              |
|-----:|-----------------------------------|
| 1    | FTAP_ERR_PROTOCOL                 |
| 2    | FTAP_ERR_UNSUPPORTED_VERSION      |
| 3    | FTAP_ERR_UNSUPPORTED_FIELD        |
| 4    | FTAP_ERR_INVALID_STATE            |
| 5    | FTAP_ERR_MESSAGE_TOO_LARGE        |
| 6    | FTAP_ERR_ACCESS_DENIED            |
| 7    | FTAP_ERR_INVALID_CREDENTIALS      |
| 8    | FTAP_ERR_ACCOUNT_UNAVAILABLE      |
| 9    | FTAP_ERR_RATE_LIMITED             |
| 10   | FTAP_ERR_SESSION_REVOKED          |
| 11   | FTAP_ERR_DATABASE_UNAVAILABLE     |
| 12   | FTAP_ERR_INTERNAL                 |

Extern sichtbare Loginfehler unterscheiden grundsätzlich nicht zwischen:

- unbekanntem Benutzer,
- falschem Passwort,
- gesperrtem Konto.

Internes Audit darf die genaue Ursache enthalten.

## 22. Timeouts

FTAP/1 verwendet mindestens folgende konfigurierbare Timeouts:

```text
HELLO-Timeout
Anfrage-Timeout
Authentifizierungs-Timeout
Schreib-Timeout
Heartbeat-Timeout
```

Ein Timeout führt zu einer kontrollierten Fehlerbehandlung und gegebenenfalls
zum Schließen der Verbindung.

## 23. Verhalten bei Auth-Daemon-Ausfall

### 23.1 Sitzunggebundene Terminalverbindungen

Wird die FTAP-Verbindung während einer aktiven Terminal-Sitzung unerwartet
geschlossen, beendet `mbsebbs` die Sitzung.

Für eine `SESSION_BOUND`-Verbindung gibt es in FTAP 1.1 keine automatische
Wiederanbindung an einen neu gestarteten Auth-Daemon. Die Benutzerin oder der
Benutzer meldet sich anschließend neu an.

### 23.2 Vertrauenswürdige Service-Verbindungen

Der Verlust einer `SERVICE_BOUND`-Verbindung invalidiert keine API-Sitzungen
und keine Access- oder Refresh-Tokens.

Diese Zustände liegen verbindlich in PostgreSQL und sind nicht an eine
bestimmte FTAP-Service-Verbindung gebunden.

`fortytwo-api`:

1. markiert alle auf der verlorenen Verbindung noch offenen FTAP-Anfragen als
   fehlgeschlagen,
2. verwendet daraus keine teilweise empfangenen oder zwischengespeicherten
   Autorisierungsergebnisse,
3. baut seinen Service-Verbindungspool mit begrenztem Backoff neu auf,
4. führt für jede neue Verbindung erneut `HELLO` und
   `SERVICE_BIND_REQUEST` aus,
5. nimmt neue Authentifizierungs- und Autorisierungsanfragen erst nach
   erfolgreichem `SERVICE_BIND_RESULT` wieder an.

Laufende HTTP-Anfragen dürfen kontrolliert fehlschlagen oder nach einer
sicheren, endpunktspezifischen Wiederholungsregel erneut gestellt werden.
Nicht idempotente Anfragen werden niemals blind wiederholt.

Ein Neustart von `fortytwo-authd` meldet API-Benutzer nicht automatisch ab.
Nach Wiederherstellung des Verbindungspools werden ihre Access-Tokens erneut
gegen den aktuellen Datenbankzustand geprüft.

Solange keine funktionsfähige Service-Verbindung verfügbar ist, gilt
„fail closed“: `fortytwo-api` erteilt keine Berechtigung aufgrund alter,
lokal zwischengespeicherter oder vermuteter Zustände.

## 24. Zurückgestellte Authentifizierungsverfahren

### 24.1 TOTP und weitere Mehrfaktorverfahren

TOTP und weitere Mehrfaktorverfahren sind nicht Bestandteil von FTAP/1.1.

Spätere Versionen ergänzen dafür neue Nachrichtentypen, beispielsweise:

```text
AUTH_TOTP_CHALLENGE
AUTH_TOTP_RESPONSE
AUTH_TOTP_RESULT
```

### 24.2 Interne SSH-Public-Key-Anmeldung

Die Zuordnung und Prüfung von SSH-Schlüsseln gegen `bbs_ssh_keys` ist ebenfalls
nicht Bestandteil von FTAP/1.1.

Die erste FTAP-Stufe unterstützt SSH als Transport mit der internen
Passwortanmeldung:

```text
PROTOCOL = ssh
AUTH_METHOD = password
```

Eine FortyTwo-eigene Public-Key-Anmeldung wird erst nach separater
Spezifikation von Fingerprint-, Challenge- und Widerrufsablauf ergänzt.

Bis dahin wird kein SSH-Schlüssel als interne FortyTwo-Benutzeridentität
akzeptiert.

Die Bedeutung bestehender FTAP/1-Nachrichten wird durch spätere Erweiterungen
nicht verändert.

## 25. Sicherheitsregeln

- Passwörter erscheinen niemals in Logs.
- Passwörter erscheinen niemals in Fehlermeldungen.
- Payload-Längen werden vor Speicherzugriffen geprüft.
- Die TLV-Summe muss die deklarierte Payload-Länge exakt treffen.
- Doppelte nicht wiederholbare Felder führen zum Protokollfehler.
- Ganzzahlüberläufe bei Längenberechnungen führen zum Abbruch.
- Teilweise gelesene Header und Payloads werden korrekt behandelt.
- `read()` und `write()` dürfen nicht als vollständig abgeschlossen
  vorausgesetzt werden.
- `SIGPIPE` darf den Auth-Daemon nicht unkontrolliert beenden.
- Unbekannte Zustandsübergänge werden abgewiesen.
- Doppelte noch offene Request-IDs führen zum Verbindungsabbruch.
- Fehler führen niemals automatisch zu einer Berechtigung.
- Sensible Speicherbereiche werden nach Benutzung sicher gelöscht.
- Keine FTAP-Nachricht enthält PostgreSQL-Zugangsdaten oder Passwort-Hashes.

## 26. Testanforderungen

Mindestens getestet werden:

- gültiger HELLO-Ablauf,
- falscher Magic-Wert,
- unbekannte Major-Version,
- korrekt kodierte `uint16`-Versionsfelder,
- unbekanntes kritisches Feld,
- übergroße Payload,
- abgeschnittener Header,
- abgeschnittene TLV-Payload,
- Ganzzahlüberlauf bei Feldlängen,
- ungültige UTF-8-Eingabe,
- ungültiger Zustandsübergang,
- doppeltes nicht wiederholbares Feld,
- mehrere `CAPABILITY`-Felder in `AUTHZ_CHECK_REQUEST`,
- TLV-Summe kleiner oder größer als deklarierte Payload-Länge,
- falsches Passwort,
- temporäre Schutzsperre,
- administrative Sperre,
- erfolgreicher Login,
- geerbter FD 3,
- Kontextabfrage nach `execve()`,
- `SERVICE_BIND_REQUEST` mit erlaubten und unerlaubten Peer-Credentials,
- mehrere parallele Service-Anfragen mit Antworten in anderer Reihenfolge,
- Kollision mit einer noch offenen Request-ID,
- Verbindungsabbruch mit mehreren offenen Service-Anfragen,
- Wiederaufbau des Service-Verbindungspools nach Auth-Daemon-Neustart,
- Fortbestand gültiger API-Sitzungen nach Auth-Daemon-Neustart,
- Fail-closed-Verhalten bei nicht verfügbarem Service-Pool,
- Tokenkontext über `ACCESS_TOKEN`,
- Zurückweisung einer bloßen `SESSION_ID` als Service-Credential,
- API-Autorisierungsprüfung mit `ACCESS_TOKEN`,
- HTTP-Rate-Limiting in `fortytwo-api` getrennt von defensiven
  Dienstgrenzen in `fortytwo-authd`,
- Berechtigungsänderung per Server-Push,
- Server-Push während einer ausstehenden Clientanfrage,
- Sitzungswiderruf per Server-Push,
- Eintreffen einer normalen Antwort nach `SESSION_REVOKED`,
- normaler Logout,
- unerwarteter Socketabbruch,
- Neustart von `fortytwo-authd`,
- zwei parallele Benutzer,
- zwei parallele Sitzungen desselben Benutzers.

Alle C-Komponenten werden zusätzlich mit ASan und UBSan geprüft.
