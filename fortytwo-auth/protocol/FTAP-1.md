# FortyTwo Authentication Protocol – FTAP/1

Status: Interne Protokollspezifikation
Dokumentrevision: 1.5
Wire-Version: FTAP 1.3
Transport: lokaler Unix-Domain-Socket
Standardpfad: `/run/fortytwo/auth.sock`

Dokumentrevision 1.5 ergänzt die verbindungsgebundene Telnet-Registrierung:

- den Zustand `REGISTERING`;
- Begin, Commit und bestätigten Abort;
- serverseitig erzeugte Registrierungs-, Benutzer- und Legacy-Identitäten;
- ein nicht anmeldbares Pending-Konto vor der MBSE-Provisionierung;
- Aktivierung und erste Telnet-Sitzung erst beim Commit;
- registrierungsspezifische Fehler ohne Offenlegung fremder Profildaten.

Dokumentrevision 1.4 ergänzt für den MBSE-Sitzungsbootstrap:

- explizite `LEGACY_NAME`-Bindung für den achtstelligen `users.data`-Schlüssel;
- Pflichtfeld in Passwort- und Sitzungskontext-Ergebnissen;
- keine Ableitung der Legacy-Identität aus `LOGNAME`, `USER` oder Clientdaten.

Dokumentrevision 1.3 konsolidierte vor Beginn der Implementierung:

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
Minor-Version: 3
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
| Kontostatus                  | 16 Byte |
| Capability-Name              | 96 Byte |
| Protokollname                | 16 Byte |
| Authentifizierungsmethode    | 32 Byte |
| TTY-Gerät                    | 128 Byte |
| Node-ID                      | 64 Byte |
| IP-Adresse                   | 45 Byte |
| Clientname                   | 64 Byte |
| Clientversion                | 32 Byte |
| Dienstname                   | 64 Byte |
| Ressourcentyp                | 64 Byte |
| Ressourcenkennung            | 128 Byte |
| Sitzungsende-Grund           | 64 Byte |
| Widerrufsgrund               | 64 Byte |
| Registrierungszustand        | 24 Byte |
| Registrierungsgrund          | 64 Byte |
| Fehlertext                   | 256 Byte |
| Passwort                     | 1024 Byte |
| Opakes Access-Token          | 512 Byte |

Der Empfänger prüft alle Längen vor einer Speicherreservierung oder Kopie.

`ENDED_REASON`, `REVOKE_REASON` und `REGISTRATION_REASON` sind
maschinenlesbare Kennungen. Zulässig
sind 1 bis 64 ASCII-Byte. Das erste Zeichen muss ein Kleinbuchstabe sein; die
folgenden Zeichen dürfen Kleinbuchstaben, Ziffern, Punkt, Bindestrich oder
Unterstrich sein. Beispiele:

```text
normal_logout
account_locked
password_changed
authd_shutdown
protocol_error
```

Freitext oder eine lokalisierte Erklärung gehört nicht in diese Felder.

## 8. Verbindungszustände

Eine FTAP-Verbindung befindet sich immer in genau einem Zustand:

```text
CONNECTED
HELLO_COMPLETE
REGISTERING
AUTHENTICATING
SESSION_BOUND
SERVICE_BOUND
CLOSING
```

Erlaubte Übergänge:

```text
Terminalverbindung mit Anmeldung:

CONNECTED
    -> HELLO_COMPLETE
    -> AUTHENTICATING
    -> SESSION_BOUND
    -> CLOSING

Telnet-Registrierung:

CONNECTED
    -> HELLO_COMPLETE
    -> REGISTERING
    -> SESSION_BOUND oder HELLO_COMPLETE
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

### 9.7 Registrierung

| Wert | Name                        |
|-----:|-----------------------------|
| 150  | REGISTRATION_BEGIN_REQUEST  |
| 151  | REGISTRATION_BEGIN_RESULT   |
| 152  | REGISTRATION_COMMIT_REQUEST |
| 153  | REGISTRATION_COMMIT_RESULT  |
| 154  | REGISTRATION_ABORT_REQUEST  |
| 155  | REGISTRATION_ABORT_RESULT   |

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
| 27   | LEGACY_NAME             | Text           |
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
| 62   | REGISTRATION_ID          | UUID           |
| 63   | REGISTRATION_STATE       | Text           |
| 64   | REGISTRATION_REASON      | Text           |

`ACCOUNT_STATE` ist in FTAP 1.3 ausschließlich in
`REGISTRATION_BEGIN_RESULT` und `REGISTRATION_COMMIT_RESULT` zulässig. Der
Client darf diesen Wert niemals vorgeben. Zulässige Werte sind dort `pending`
beziehungsweise `active`. In allen anderen Nachrichten führt das Feld zu
`FTAP_STATUS_ERR_FORBIDDEN_FIELD`. Laufende Clients erhalten bei einer späteren
sicherheitsrelevanten Änderung gegebenenfalls `SESSION_REVOKED`, statt selbst
einen möglicherweise veralteten Status zu bewerten.

`LEGACY_NAME` ist der explizit administrativ gebundene Schlüssel des
bestehenden MBSE-`users.data`-Datensatzes. Er besteht aus 1 bis 8
kleingeschriebenen ASCII-Zeichen. Das erste Zeichen ist `[a-z0-9]`, weitere
Zeichen dürfen zusätzlich `.`, `_` oder `-` sein. Clients dürfen diesen Wert
nicht vorgeben; der Auth-Dienst lädt ihn zusammen mit der UUID-Identität aus
PostgreSQL. Eine Identität ohne Bindung kann keine Terminal-Sitzung eröffnen.

`REGISTRATION_ID` wird ausschließlich von `fortytwo-authd` erzeugt und bindet
einen Pending-Versuch an genau eine FTAP-Verbindung. `REGISTRATION_STATE`
verwendet ausschließlich `pending_legacy`, `completed`, `aborted` oder
`failed`. `REGISTRATION_REASON` ist eine maschinenlesbare Kennung und niemals
ein Passwort-, Profil- oder Fehlerfreitext.

Die numerische Feld-ID ist nicht an die interne Kardinalitätsverwaltung einer
Implementierung gekoppelt. Implementierungen müssen deshalb auch Feld-IDs über
63 verarbeiten können. Erlaubte, erforderliche und wiederholbare Felder werden
über Regeln nach Feld-ID bestimmt, nicht durch Verschieben der Feld-ID in eine
64-Bit-Bitmaske.

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

Für diesen Implementierungsstand muss `SUPPORTED_MINOR` mindestens `3` sein. Ein FTAP-1.2-Client wird kontrolliert mit `FTAP_ERR_UNSUPPORTED_VERSION` abgewiesen.

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

## 13. Telnet-Registrierung

Registrierung ist in FTAP 1.3 ausschließlich für einen zugelassenen lokalen
Loginprozess mit:

```text
PROTOCOL    = telnet
AUTH_METHOD = password
```

erlaubt. Eine ausgeblendete Clientoption ist keine Sicherheitsgrenze. Der
Daemon muss Registrierung zusätzlich administrativ aktiviert haben.

### 13.1 Begin-Anfrage

`REGISTRATION_BEGIN_REQUEST` ist nur in `HELLO_COMPLETE` zulässig.

Pflichtfelder:

```text
LOGIN_NAME
DISPLAY_NAME
PASSWORD
PROTOCOL
SOURCE_IP
AUTH_METHOD
```

Optionale Felder:

```text
TTY_DEVICE
NODE_ID
```

`USER_ID`, `REGISTRATION_ID`, `LEGACY_NAME`, `ACCOUNT_STATE`, `SESSION_ID` und
`CAPABILITY` sind in der Anfrage verboten. UUID, Registrierungs-ID und
Legacy-Schlüssel werden ausschließlich serverseitig erzeugt.

Der Daemon:

1. prüft die administrative Freigabe und Registrierungsgrenzen;
2. kanonisiert und validiert den Loginnamen;
3. validiert Anzeigename, Passwort und kanonische Quell-IP;
4. erzeugt den Argon2id-Hash im gemeinsam begrenzten Worker-Pool;
5. erzeugt UUID, Registrierungs-ID und Legacy-Schlüssel;
6. legt Benutzer, Profil, Credential, Legacy-Bindung, Registrierungsversuch
   und Audit atomar in PostgreSQL an;
7. bindet den Versuch an diese FTAP-Verbindung.

Nach erfolgreichem Begin gilt:

```text
bbs_users.account_state = pending
keine Rolle bbs_user
keine Rolle ssh_access
keine Terminalsitzung
```

Der Klartext des Passworts und der Argon2id-PHC-String werden nie über FTAP
zurückgesendet.

### 13.2 Begin-Ergebnis

`REGISTRATION_BEGIN_RESULT` besitzt das Flag `RESPONSE` und enthält:

```text
REGISTRATION_ID
REGISTRATION_STATE = pending_legacy
USER_ID
LOGIN_NAME
DISPLAY_NAME
LEGACY_NAME
ACCOUNT_STATE = pending
```

Die Verbindung befindet sich anschließend im Zustand `REGISTERING`.

### 13.3 Commit

Nach dauerhaft erfolgreicher MBSE-Provisionierung sendet der Client im Zustand
`REGISTERING`:

```text
REGISTRATION_COMMIT_REQUEST
REGISTRATION_ID
```

Die ID muss bytegenau zu dem an diese Verbindung gebundenen Versuch gehören.
Der Client sendet keine Benutzer-ID und keinen Legacy-Schlüssel zurück.

Der Daemon führt atomar aus:

- Pending-Zustand und Bindung erneut prüfen;
- Rolle `bbs_user` zuweisen;
- Rolle `ssh_access` nicht zuweisen;
- Konto auf `active` setzen;
- `authz_revision` erhöhen;
- Registrierungsversuch auf `completed` setzen;
- erste Telnet-Terminalsitzung erzeugen;
- `auth.registration_completed` und `auth.login_succeeded` auditieren.

`REGISTRATION_COMMIT_RESULT` besitzt das Flag `RESPONSE` und enthält:

```text
REGISTRATION_ID
REGISTRATION_STATE = completed
USER_ID
SESSION_ID
LOGIN_NAME
DISPLAY_NAME
LEGACY_NAME
ACCOUNT_STATE = active
PROTOCOL = telnet
AUTH_METHOD = password
AUTH_EPOCH
AUTHZ_REVISION
```

`CAPABILITY` darf null- bis mehrfach vorkommen. Nach Erfolg wechselt die
Verbindung in `SESSION_BOUND` und ist für den späteren FD-3-Handoff geeignet.

### 13.4 Bestätigter Abbruch

Ein Abbruch ist eine bestätigte Anfrage und keine einseitige Meldung:

```text
REGISTRATION_ABORT_REQUEST
REGISTRATION_ABORT_RESULT
```

Die Anfrage ist nur in `REGISTERING` zulässig und enthält zwingend:

```text
REGISTRATION_ID
```

Optional:

```text
REGISTRATION_REASON
```

Fehlt der Grund, verwendet der Daemon `client_cancelled`. Ein Client darf
hier ausschließlich `client_cancelled` oder `legacy_write_failed` senden.
Gründe wie `client_disconnected`, `daemon_shutdown`, `database_failure`,
`registration_timeout` und `internal_error` werden ausschließlich serverseitig
für Audit und Rekonsiliation erzeugt.

Der Daemon markiert den Versuch atomar als `aborted`, hinterlässt kein
anmeldbares Konto, keine Rolle und keine Sitzung. Credential, Profil und
Legacy-Bindung werden entfernt; die UUID und der Registrierungsdatensatz bleiben
für Audit und Historie erhalten.

Das Ergebnis enthält:

```text
REGISTRATION_ID
REGISTRATION_STATE = aborted
USER_ID
```

Nach erfolgreichem Abort kehrt die Verbindung in `HELLO_COMPLETE` zurück und
darf einen neuen Begin-Versuch senden.

### 13.5 Verbindungsverlust und Neustart

Während der Hash-Erzeugung existiert noch kein Datenbankversuch. Eine späte
Worker-Completion wird über Verbindungs-ID, Generation, Request-ID und Job-ID
als veraltet erkannt und vollständig gelöscht.

Nach erfolgreichem Begin versucht der Daemon bei Socketverlust einen atomaren
Abort mit `client_disconnected`. Ist PostgreSQL nicht verfügbar, bleibt das
Konto nicht anmeldbar und wird nach seiner Ablaufzeit als `failed` bereinigt.

Eine Pending-Registrierung wird nach einem Daemon-Neustart nicht an eine neue
FTAP-Verbindung gebunden. FTAP 1.3 besitzt keinen Wiederaufnahme-Token für
Registrierungen.

### 13.6 Eingabegrenzen

Loginname:

```text
^[a-z0-9][a-z0-9._-]{0,31}$
```

ASCII-Großbuchstaben werden vor der Prüfung in Kleinbuchstaben umgewandelt.

Anzeigename:

```text
1 bis 64 UTF-8-Byte
kein NUL
keine C0- oder C1-Steuerzeichen
keine führenden oder abschließenden ASCII-Leerzeichen
```

Passwort für neue Registrierungen:

```text
12 bis 1024 UTF-8-Byte
kein NUL
keine Normalisierung oder Trimmung
```

`SOURCE_IP` ist bei Registrierung Pflicht und muss eine kanonische IPv4- oder
IPv6-Darstellung enthalten.

## 14. Passwortanmeldung

`AUTH_PASSWORD_REQUEST` darf nur von dafür zugelassenen Loginprozessen
gesendet werden.

Pflichtfelder:

```text
LOGIN_NAME
PASSWORD
PROTOCOL
AUTH_METHOD
```

Für `AUTH_PASSWORD_REQUEST` sind in FTAP/1.3 ausschließlich folgende Werte
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
5. prüft die zum angeforderten Transport gehörende Capability,
6. erzeugt bei Erfolg eine Terminal-Sitzung,
7. bindet diese Sitzung an die bestehende Socket-Verbindung,
8. löscht den Klartextpasswortpuffer.

Transport und erforderliche Capability sind verbindlich zugeordnet:

```text
telnet -> terminal.login.telnet
ssh    -> terminal.login.ssh
local  -> terminal.login.local
```

Fehlt nach erfolgreicher Passwortprüfung die erforderliche Capability, wird
keine Terminal-Sitzung erzeugt. Der Daemon schreibt ein internes
`auth.login_rejected`-Audit mit dem Grund `transport_not_authorized` und
antwortet mit `FTAP_ERR_ACCESS_DENIED`.

Bei Erfolg enthält `AUTH_PASSWORD_RESULT` mindestens:

```text
USER_ID
SESSION_ID
LOGIN_NAME
DISPLAY_NAME
LEGACY_NAME
AUTH_EPOCH
AUTHZ_REVISION
```

Zusätzlich darf `CAPABILITY` mehrfach vorkommen.

Nach erfolgreicher Anmeldung wechselt die Verbindung in den Zustand
`SESSION_BOUND`.

Das Passwort wird niemals in einer Antwort zurückgesendet.

## 15. Geerbter Sitzungs-Dateideskriptor

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

## 16. Sitzungskontext

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
LEGACY_NAME
PROTOCOL
AUTH_METHOD
AUTH_EPOCH
AUTHZ_REVISION
```

`CAPABILITY` darf in dieser Ergebnisnachricht null- bis mehrfach vorkommen.

## 17. Autorisierungsprüfung

Für ressourcenbezogene Prüfungen sendet der Client:

```text
AUTHZ_CHECK_REQUEST
```

In jeder `AUTHZ_CHECK_REQUEST` ist genau ein `CAPABILITY`-Feld erlaubt.

Mehrere Capability-Felder sind ein Protokollfehler; es gibt keine implizite
UND- oder ODER-Semantik.

### 17.1 Sitzunggebundene Terminalverbindung

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

### 17.2 Vertrauenswürdige Service-Verbindung

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

### 17.3 Server-Push und ausstehende Anfragen

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

## 18. Berechtigungsänderungen

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

## 19. Sitzungswiderruf

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

## 20. Heartbeat

Aktive Terminalprozesse dürfen regelmäßig `SESSION_HEARTBEAT` senden.

Der Auth-Daemon aktualisiert damit `last_seen_at`.

Ein Heartbeat enthält keine frei gewählte Benutzeridentität.

Das genaue Intervall wird später konfigurierbar festgelegt.

## 21. Geordnetes Sitzungsende

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

## 22. Fehlercodes

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
| 13   | FTAP_ERR_LOGIN_NAME_UNAVAILABLE  |
| 14   | FTAP_ERR_PASSWORD_POLICY         |

Extern sichtbare Loginfehler unterscheiden grundsätzlich nicht zwischen:

- unbekanntem Benutzer,
- falschem Passwort,
- gesperrtem Konto.

Eine transportbezogene Ablehnung über `FTAP_ERR_ACCESS_DENIED` darf erst nach
korrekter Passwortprüfung verständlich benannt werden. Dadurch gibt die
Meldung keine Information über unbekannte Konten oder falsche Passwörter preis.

Internes Audit darf die genaue Ursache enthalten.

`FTAP_ERR_LOGIN_NAME_UNAVAILABLE` wird nur im ausdrücklichen
Registrierungsvorgang verwendet und gibt keine Profil- oder Kontostatusdaten
preis. `FTAP_ERR_PASSWORD_POLICY` nennt keine Passwortinhalte und keine
unnötigen Prüfdaten.

## 23. Timeouts

FTAP/1 verwendet mindestens folgende konfigurierbare Timeouts:

```text
HELLO-Timeout
Anfrage-Timeout
Authentifizierungs-Timeout
Registrierungs-Timeout
Schreib-Timeout
Heartbeat-Timeout
```

Ein Timeout führt zu einer kontrollierten Fehlerbehandlung und gegebenenfalls
zum Schließen der Verbindung.

## 24. Verhalten bei Auth-Daemon-Ausfall

### 24.1 Sitzunggebundene Terminalverbindungen

Wird die FTAP-Verbindung während einer aktiven Terminal-Sitzung unerwartet
geschlossen, beendet `mbsebbs` die Sitzung.

Für eine `SESSION_BOUND`-Verbindung gibt es in FTAP 1.3 keine automatische
Wiederanbindung an einen neu gestarteten Auth-Daemon. Die Benutzerin oder der
Benutzer meldet sich anschließend neu an.

### 24.2 Vertrauenswürdige Service-Verbindungen

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

## 25. Zurückgestellte Authentifizierungsverfahren

### 25.1 TOTP und weitere Mehrfaktorverfahren

TOTP und weitere Mehrfaktorverfahren sind nicht Bestandteil von FTAP/1.3.

Spätere Versionen ergänzen dafür neue Nachrichtentypen, beispielsweise:

```text
AUTH_TOTP_CHALLENGE
AUTH_TOTP_RESPONSE
AUTH_TOTP_RESULT
```

### 25.2 Interne SSH-Public-Key-Anmeldung

Die Zuordnung und Prüfung von SSH-Schlüsseln gegen `bbs_ssh_keys` ist ebenfalls
nicht Bestandteil von FTAP/1.3.

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

## 26. Sicherheitsregeln

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

## 27. Testanforderungen

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
- vollständige FTAP-1.3-Registrierung nur über Telnet,
- Begin ohne Rolle und ohne Sitzung,
- Commit mit `bbs_user`, aber ohne `ssh_access`,
- bestätigter Abort und Rückkehr zu `HELLO_COMPLETE`,
- fremde oder veraltete `REGISTRATION_ID`,
- Socketabbruch während Hashing und Pending-Zustand,
- Timeout-Bereinigung ohne anmeldbares Konto,
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
