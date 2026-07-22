# FortyTwo BBS – B5.5 Zugriffsinventur der Benutzerfelder

**Stand:** 22. Juli 2026
**Phase:** B5.5 – Leser-/Schreiber-Inventur von `struct userrec`

## 1. Zweck

Diese Inventur erfasst die direkten Feldzugriffe und die Operationen auf
vollständigen Legacy-Benutzerdatensätzen im produktiven Quellbaum.

Sie ergänzt die in B5.4 angelegte Feldmatrix. Während B5.4 festhält,
welche Felder existieren und welche davon im `mbsetup`-Benutzereditor
sichtbar sind, dokumentiert B5.5, wo diese Felder im gesamten Projekt
gelesen oder verändert werden.

Die Phase verändert weder `users.data` noch PostgreSQL und führt keinen
automatischen Datenabgleich durch.

## 2. Analysierte Zugriffsarten

### 2.1 Direkte Feldzugriffe

Direkte Feldzugriffe sind Ausdrücke wie:

```c
usr.Security
usrconfig.sHandle
exitinfo.iTimeUsed
record->Name
```

Sie werden in folgende Klassen eingeordnet:

- `read`: Feldwert wird gelesen,
- `write`: Feldwert wird ersetzt oder initialisiert,
- `read-write`: Feldwert wird gelesen und verändert,
- `metadata`: nur Größe oder Layout des Feldes wird verwendet.

### 2.2 Ganzsatzoperationen

Ganzsatzoperationen betreffen einen vollständigen `struct userrec`,
beispielsweise durch `fread()`, `fwrite()`, `memset()`, Prüfsummenbildung
oder Übergabe an geprüfte Hilfsfunktionen.

Sie werden in folgende Klassen eingeordnet:

- `record-read`: vollständiger Datensatz wird gelesen,
- `record-write`: vollständiger Datensatz wird überschrieben,
- `record-read-write`: Datensatz wird kontrolliert in-place verändert,
- `metadata`: nur Größe oder Layout des Datensatzes wird geprüft.

## 3. Gesamtergebnis

```text
Felder in struct userrec:             72
Felder mit direkten Zugriffen:        58
Felder ohne direkte Zugriffe:         14
Direkte Member-Fundstellen:           991
Quelldateien mit direkten Zugriffen:  44

Ganzsatz-Fundstellen:                 140
Ganzsatzleser:                         23
Ganzsatzschreiber:                     57
Ganzsatz-Read-Modify-Write:              3
Ganzsatz-Metadatenzugriffe:             57
Quelldateien mit Ganzsatzoperationen:   24
Unklare Ganzsatzkandidaten:              0
```

## 4. Zentrale Migrationsfolge

Die 14 Felder ohne direkte Memberzugriffe sind nicht automatisch
unbenutzt. Sie werden weiterhin durch vollständige Datensatzoperationen
gelesen, kopiert und zurückgeschrieben.

Daraus folgt verbindlich:

> Ein Feld darf nicht allein deshalb entfernt oder ignoriert werden,
> weil kein direkter Ausdruck wie `usr.<Feld>` gefunden wurde.

Vor jeder strukturellen Änderung müssen sowohl die direkten Feldzugriffe
als auch alle Ganzsatzleser und Ganzsatzschreiber berücksichtigt werden.

## 5. Felder ohne direkten Memberzugriff

Die folgenden 14 Felder erscheinen im untersuchten Produktionsquellbaum
nicht als direkter Feldzugriff:

```text
xChat
xFsMsged
xScreenLen
xHangUps
Paged
LastPktNum
iLastFileGroup
iTransferTime
iLastMsgGroup
CrtDef
Protocol
IEMSI
ieMNU
ieTAB
```

Sie bleiben dennoch Bestandteil des binären Legacy-Datensatzes und werden
über Ganzsatzoperationen transportiert.

## 6. Feldübersicht

| Legacy-Feld | Lesen | Schreiben | Read-Modify-Write | Metadaten | Dateien | Einordnung |
|---|---:|---:|---:|---:|---:|---|
| sUserName | 95 | 4 | 4 | 3 | 27 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Name | 158 | 4 | 0 | 3 | 33 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| xPassword | 2 | 1 | 0 | 0 | 1 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sVoicePhone | 10 | 4 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sDataPhone | 9 | 5 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sLocation | 15 | 4 | 1 | 0 | 10 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| address | 25 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sDateOfBirth | 9 | 5 | 0 | 0 | 6 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| tFirstLoginDate | 5 | 2 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| tLastLoginDate | 11 | 4 | 0 | 0 | 8 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Security | 91 | 6 | 0 | 0 | 18 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sComment | 9 | 3 | 0 | 3 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sExpiryDate | 4 | 4 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| ExpirySec | 3 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sSex | 5 | 7 | 0 | 0 | 3 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Hidden | 6 | 1 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| HotKeys | 7 | 7 | 0 | 0 | 7 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| GraphMode | 20 | 7 | 0 | 0 | 9 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Deleted | 14 | 2 | 0 | 0 | 9 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| NeverDelete | 3 | 1 | 0 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| xChat | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| LockedOut | 8 | 1 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| DoNotDisturb | 7 | 4 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Cls | 2 | 3 | 0 | 0 | 3 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| More | 2 | 3 | 0 | 0 | 3 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| xFsMsged | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| MailScan | 6 | 8 | 0 | 0 | 6 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Guest | 5 | 1 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| OL_ExtInfo | 8 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iTotalCalls | 9 | 0 | 2 | 0 | 8 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iTimeLeft | 18 | 7 | 1 | 0 | 9 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iConnectTime | 3 | 2 | 1 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iTimeUsed | 4 | 3 | 1 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| xScreenLen | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| tLastPwdChange | 2 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| xHangUps | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| Credit | 3 | 1 | 0 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Paged | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| MsgEditor | 7 | 9 | 0 | 0 | 7 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| LastPktNum | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| Archiver | 10 | 6 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iLastFileArea | 2 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iLastFileGroup | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| sProtocol | 6 | 5 | 1 | 0 | 7 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Downloads | 7 | 0 | 2 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Uploads | 5 | 0 | 2 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| UploadK | 6 | 0 | 1 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| DownloadK | 5 | 0 | 1 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| DownloadKToday | 4 | 1 | 2 | 0 | 3 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| UploadKToday | 1 | 0 | 1 | 0 | 1 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iTransferTime | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| iLastMsgArea | 3 | 3 | 0 | 0 | 5 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iLastMsgGroup | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| iPosted | 4 | 0 | 5 | 0 | 7 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iLanguage | 4 | 4 | 0 | 0 | 6 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| sHandle | 46 | 7 | 0 | 4 | 15 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| iStatus | 0 | 1 | 0 | 0 | 1 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| DownloadsToday | 1 | 1 | 0 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| CrtDef | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| Protocol | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| IEMSI | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| ieMNU | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| ieTAB | 0 | 0 | 0 | 0 | 0 | nur über vollständige Datensätze transportiert |
| ieASCII8 | 0 | 2 | 0 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| ieNEWS | 6 | 5 | 0 | 0 | 6 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| ieFILE | 6 | 8 | 0 | 0 | 6 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Email | 11 | 3 | 0 | 0 | 10 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| FSemacs | 6 | 3 | 0 | 0 | 4 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Password | 11 | 6 | 0 | 7 | 9 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| Charset | 21 | 3 | 0 | 0 | 9 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| OLRext | 3 | 3 | 1 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |
| OLRlast | 1 | 2 | 0 | 0 | 2 | direkt verwendet und zusätzlich von Ganzsatzoperationen betroffen |

## 7. Ganzsatzoperationen

| Zugriffsart | Fundstellen |
|---|---:|
| `record-read` | 23 |
| `record-write` | 57 |
| `record-read-write` | 3 |
| `metadata` | 57 |

Alle zuvor als Pointer-Escape oder unbekannte Wertübergabe erkannten
Kandidaten wurden anhand der aufgerufenen Funktionen geprüft und
eindeutig klassifiziert.

Besonders relevant sind:

- `read_exact_at(..., &record, ...)` als vollständiger Schreibzugriff,
- `record_identifier_matches(&record, ...)` als Lesezugriff,
- `write_record_at(..., &record, ...)` als Lesezugriff,
- `build_record(..., &record)` als vollständiger Schreibzugriff,
- `TerminateUserRecordStrings(&usrconfig)` als In-place-Änderung,
- `upd_crc32(&usrconfig, ...)` als vollständiger Lesezugriff.

## 8. Verdeckte In-place-Feldänderungen

Die direkte Feldanalyse berücksichtigt zusätzlich historische
Hilfsfunktionen, die übergebene Zeichenfelder verändern:

- `tl()` wandelt den Text direkt in Kleinbuchstaben um,
- `tu()` wandelt den Text direkt in Großbuchstaben um,
- `tlf()` verändert das erste Zeichen direkt.

Dadurch wurden sechs zunächst wie reine Leser wirkende Zugriffe korrekt
als Read-Modify-Write klassifiziert.

Ein auffälliger Altcode-Seiteneffekt ist:

```c
tu(exitinfo.sLocation)
```

Die Ausgabe einer Door-Datei kann dadurch den im Speicher liegenden
Standorttext verändern.

## 9. Analysierte Quelldateien

### 9.1 Direkte Feldzugriffe

```text
fortytwo-auth/src/legacy_userdb.c
fortytwo-auth/src/legacy_userdb_provision.c
lib/dbuser.c
lib/jammsg.c
mbfido/ftn2rfc.c
mbfido/mbmsg.c
mbfido/scan.c
mbfido/storenet.c
mbnntp/auth.c
mbnntp/commands.c
mbnntp/rfc2ftn.c
mbsebbs/bye.c
mbsebbs/change.c
mbsebbs/chat.c
mbsebbs/dispfile.c
mbsebbs/door.c
mbsebbs/email.c
mbsebbs/file.c
mbsebbs/filesub.c
mbsebbs/fsedit.c
mbsebbs/funcs.c
mbsebbs/lastcallers.c
mbsebbs/mail.c
mbsebbs/menu.c
mbsebbs/misc.c
mbsebbs/msgutil.c
mbsebbs/newuser.c
mbsebbs/offline.c
mbsebbs/oneline.c
mbsebbs/page.c
mbsebbs/pop3.c
mbsebbs/signature.c
mbsebbs/term.c
mbsebbs/timecheck.c
mbsebbs/timestats.c
mbsebbs/transfer.c
mbsebbs/user.c
mbsebbs/userlist.c
mbsebbs/whoson.c
mbsebbs/zmrecv.c
mbsetup/m_limits.c
mbsetup/m_users.c
mbutils/mbuser.c
unix/mblogin.c
```

### 9.2 Ganzsatzoperationen

```text
fortytwo-auth/src/legacy_userdb.c
fortytwo-auth/src/legacy_userdb_provision.c
lib/dbuser.c
lib/jammsg.c
mbfido/mbmsg.c
mbfido/scan.c
mbnntp/auth.c
mbnntp/mbnntp.c
mbnntp/rfc2ftn.c
mbsebbs/bye.c
mbsebbs/change.c
mbsebbs/dispfile.c
mbsebbs/exitinfo.c
mbsebbs/funcs.c
mbsebbs/mail.c
mbsebbs/misc.c
mbsebbs/newuser.c
mbsebbs/user.c
mbsebbs/userlist.c
mbsebbs/whoson.c
mbsetup/m_limits.c
mbsetup/m_users.c
mbutils/mbuser.c
unix/mblogin.c
```

## 10. Reproduzierbare Detailnachweise

Die vollständigen maschinenlesbaren Fundstellen stehen in:

```text
docs/MBSETUP_USER_FIELD_ACCESS_RAW.tsv
docs/MBSETUP_USER_FIELD_ACCESS_DETAILS.tsv
docs/MBSETUP_USER_RECORD_ACCESS_RAW.tsv
docs/MBSETUP_USER_RECORD_ACCESS_DETAILS.tsv
```

Erzeugt werden sie durch:

```text
scripts/analyze_user_field_access.py
scripts/analyze_user_record_access.py
```

Jede Detailzeile enthält mindestens Zugriffsart, Quellpfad,
Zeilennummer, Spaltenposition, Variablenname, Member-Ausdruck und
die zugehörige Quellzeile.

## 11. Grenze der Analyse

Die Inventur ist eine strukturelle Quelltextanalyse und kein Ersatz für
Laufzeitbeobachtung. Makrosemantik und aufgerufene Hilfsfunktionen
wurden dort explizit ergänzt, wo sie Felder oder vollständige Datensätze
verändern.

Vor einer konkreten Migration bleiben ergänzende Laufzeittests,
Dateizugriffsbeobachtung und fachliche Bewertung der Feldsemantik
verbindlich.
