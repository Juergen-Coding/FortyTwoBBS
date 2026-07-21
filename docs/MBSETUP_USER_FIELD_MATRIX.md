# FortyTwo BBS – B5.4 Feldmatrix des mbsetup-Benutzereditors

**Stand:** 21. Juli 2026
**Phase:** B5.4 – Read-only Zuordnung von `users.data` zu PostgreSQL

## 1. Zweck

Diese Matrix erfasst alle Felder von `struct userrec` und damit eines
vollständigen Datensatzes in `etc/users.data`.

Sie dokumentiert zunächst ausschließlich:

- den tatsächlichen Legacy-Feldbestand,
- die direkte Sichtbarkeit im Benutzereditor `mbsetup/m_users.c`,
- bereits vorhandene PostgreSQL-Strukturen und vorläufige Zuordnungskandidaten,
- noch nicht entschiedene Felder ohne vorweggenommene Architekturentscheidung.

Die Phase ist read-only. Sie führt keine Datenmigration und keinen
Schreibabgleich durch.

Eine ausgefüllte PostgreSQL-Zuordnung ist in B5.4 noch keine Freigabe
für eine Migration. Sie kennzeichnet entweder einen vorläufigen
read-only Vergleichskandidaten oder eine verbindlich festgelegte
Nichtübernahme wie bei `Password` und `xPassword`.

## 2. Verbindlicher Quellbefund

```text
struct userrec:                    72 Felder
direkte Referenzen in m_users.c:  47 Felder
Ganzsatz-Passthrough:              25 Felder
Schreibmodell:                    kompletter struct userrec
Legacy-Passwortbearbeitung:       deaktiviert
```

Auch nicht sichtbare Felder werden beim Speichern des Benutzers erneut
nach `users.data` geschrieben. Sie gehören deshalb vollständig zur
Migrations- und Kompatibilitätsgrenze.

## 3. Wichtige Identitätsgrenze

`bbs_users.login_name` besitzt keine direkte 1:1-Entsprechung in
`users.data`. Es ist die moderne kanonische FortyTwo-Anmeldeidentität.

Das historische Feld `Name` ist dagegen der auf acht Zeichen begrenzte
Legacy-Schlüssel und wird ausschließlich über
`bbs_legacy_mbse_bindings.legacy_name` angebunden.

Die Felder `Password` und `xPassword` werden niemals nach PostgreSQL
übernommen. Authentifizierend ist ausschließlich der moderne
Passwort-Hash in `bbs_password_credentials.password_hash`.

## 4. Feldmatrix

| Legacy-Feld | Bedeutung laut Quellcode | Zugriff durch mbsetup | PostgreSQL-Tabelle | PostgreSQL-Spalte/Ziel | Künftige Führung | Anmerkung |
|---|---|---|---|---|---|---|
| sUserName | User First and Last Name | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_user_profiles | display_name | PostgreSQL | Bestehendes Ziel für den sichtbaren vollständigen Namen. |
| Name | Unix name | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_legacy_mbse_bindings | legacy_name | PostgreSQL | Explizite Legacy-Bindung; niemals mit login_name gleichsetzen. |
| xPassword | Keine Quellcodebeschreibung | nur als Teil des kompletten Datensatzes mitgeschrieben | — | — | PostgreSQL-Credential | Veraltetes Legacy-Passwortfeld; niemals authentifizierend verwenden. |
| sVoicePhone | Voice Number | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sDataPhone | Data/Business Number | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sLocation | Users Location | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| address | Users address | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sDateOfBirth | Date of Birth | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| tFirstLoginDate | Date of First Login | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| tLastLoginDate | Date of Last Login | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Security | User Security Level | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_user_roles / bbs_role_capabilities | Rollen- und Capability-Zuordnung | PostgreSQL | Der numerische Legacy-Level darf nicht direkt kopiert werden. |
| sComment | User Comment | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sExpiryDate | User Expiry Date | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ExpirySec | Expiry Security Level | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sSex | Users Sex | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Hidden | Hide User from Lists | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| HotKeys | Hot-Keys ON/OFF | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| GraphMode | ANSI ON/OFF | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Deleted | Deleted Status | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_users | account_state / deleted_at | PostgreSQL | Legacy-Bit wird in den konsistenten Löschzustand übersetzt. |
| NeverDelete | Never Delete User | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| xChat | Keine Quellcodebeschreibung | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| LockedOut | User is locked out | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_users | account_state / locked_reason | PostgreSQL | Administrative Sperre; nicht mit throttled_until vermischen. |
| DoNotDisturb | DoNot disturb | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Cls | CLS on/off | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| More | More prompt | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| xFsMsged | Keine Quellcodebeschreibung | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| MailScan | New Mail scan | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Guest | Is guest account | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| OL_ExtInfo | OLR extended msg info | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iTotalCalls | Total number of calls | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iTimeLeft | Time left today | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iConnectTime | Connect time this call | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iTimeUsed | Time used today | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| xScreenLen | Keine Quellcodebeschreibung | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| tLastPwdChange | Date last password chg | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_password_credentials | changed_at | PostgreSQL | Semantisch entsprechender Zeitpunkt; Wertvergleich erforderlich. |
| xHangUps | Keine Quellcodebeschreibung | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Credit | Users credit | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Paged | Times paged today | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| MsgEditor | Message Editor to use | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| LastPktNum | Todays Last packet number | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Archiver | Archiver to use | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iLastFileArea | Number of last file area | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iLastFileGroup | Number of last file group | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| sProtocol | Users default protocol | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Downloads | Total number of d/l's | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Uploads | Total number of uploads | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| UploadK | Upload KiloBytes | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| DownloadK | Download KiloBytes | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| DownloadKToday | KB Downloaded today | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| UploadKToday | KB Uploaded today | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iTransferTime | Last file transfer time | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iLastMsgArea | Number of last msg area | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iLastMsgGroup | Number of last msg group | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iPosted | Number of msgs posted | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| iLanguage | Current Language | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_user_profiles | language_code | PostgreSQL | Benötigt eine geprüfte Übersetzung vom Legacy-Sprachwert. |
| sHandle | Users Handle | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | bbs_user_profiles | handle | PostgreSQL | Bestehendes optionales Handle. |
| iStatus | WhosDoingWhat status | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| DownloadsToday | Downloads today | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| CrtDef | IEMSI Terminal emulation | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Protocol | IEMSI protocol | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| IEMSI | Is this a IEMSI session | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ieMNU | Can do ASCII download | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ieTAB | Can handle TAB character | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ieASCII8 | Can handle 8-bit IBM-PC | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ieNEWS | Show bulletins | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| ieFILE | Check for new files | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Email | Has private email box | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| FSemacs | FSedit uses emacs keys | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| Password | Plain password | nur als Teil des kompletten Datensatzes mitgeschrieben | — | — | PostgreSQL-Credential | Klartextfeld bleibt leer und wird niemals migriert. |
| Charset | Character set | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| OLRext | OLR extension counter | direkt gelesen/bearbeitet; kompletter Datensatz geschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |
| OLRlast | OLR last download date | nur als Teil des kompletten Datensatzes mitgeschrieben | noch nicht festgelegt | noch nicht festgelegt | Legacy bis zur Einzelentscheidung | Leser, Schreiber und fachliche Semantik müssen noch erfasst werden. |

## 5. Noch ausstehende Prüfungen

Für jedes noch nicht festgelegte Feld müssen vor einer Migration
mindestens folgende Punkte ermittelt werden:

- sämtliche Leser im gesamten MBSE-/FortyTwo-Quellbaum,
- sämtliche Schreiber und Aktualisierungszeitpunkte,
- fachliche Bedeutung und zulässiger Wertebereich,
- dauerhafter Datenwert, Statistik, Tageszähler oder Sitzungszustand,
- PostgreSQL-Zieltabelle und Datentyp,
- führendes System während der Übergangsphase,
- Richtung einer notwendigen Legacy-Kompatibilität,
- erforderliche Admin-Berechtigung und Audit-Ereignisse.

Bis diese Entscheidung dokumentiert ist, bleibt `users.data` für das
jeweilige Feld führend und es findet kein automatischer Schreibabgleich statt.

## 6. Prüfregel

Die Datei `scripts/check_mbsetup_user_field_matrix.py` friert den
Quellbestand fail-closed ein. Änderungen an `struct userrec` oder an den
direkten Feldreferenzen des Benutzereditors müssen bewusst geprüft und
in dieser Matrix nachgeführt werden.
