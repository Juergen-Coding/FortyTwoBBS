# B5.10 – Navigation, Sitzungs- und Kompatibilitätszustände

## Status

**Abgeschlossen.** Sämtliche nach B5.7, B5.8 und B5.9 noch offenen Felder aus `struct userrec` besitzen eine ausdrückliche Ownership- und Migrationsentscheidung.

Offene B5.10-Entscheidungen: **0**.

## Umfang und Ergebnis

| Merkmal | Anzahl |
|---|---:|
| Untersuchte Restfelder | 21 |
| Persistente PostgreSQL-Entscheidungen | 6 |
| Reine Sitzungswerte | 1 |
| Stillgelegte Legacy-Felder | 14 |
| Felder mit direkten Zugriffen | 7 |
| Felder ohne direkten Zugriff | 14 |
| Direkte Zugriffsfundstellen | 51 |

Die Feldgruppen verteilen sich wie folgt:

| Kategorie | Felder |
|---|---:|
| `comment-mailbox` | 2 |
| `navigation-state` | 4 |
| `offline-reader-state` | 3 |
| `session-runtime` | 7 |
| `iemsi-compatibility` | 5 |

## Verbindliche Architekturentscheidungen

### Administrative Kommentare

`sComment` wird als privater administrativer Vermerk nach PostgreSQL übernommen. Bekannte technische Registrierungsmarker werden nicht als menschliche Kommentare importiert. Der neue Vermerk darf weder an Doors noch an Dropfiles, Benutzerlisten oder unprivilegierte Schnittstellen ausgegeben werden.

### Interne Mailbox

`Email` ist im Legacy-Datensatz **keine E-Mail-Adresse**, sondern ein Boolescher Schalter für die private interne MBSE-Mailbox. Daraus dürfen weder Kontaktinformationen noch Login-, Rollen- oder SSH-Entscheidungen abgeleitet werden.

### Navigation

`iLastFileArea` und `iLastMsgArea` werden als Wiedereinstiegspunkte gespeichert. Gespeicherte Bereichsnummern gewähren niemals Zugriff: Der Bereich muss bei jeder Verwendung erneut existieren und für den Benutzer freigegeben sein.

`iLastFileGroup` und `iLastMsgGroup` werden nicht migriert. Gruppen werden bei Bedarf aus dem gültigen Bereich abgeleitet.

### Offline-Reader

`OLRext` und `OLRlast` bleiben als PostgreSQL-geführter Offline-Reader-Zustand erhalten. Zähler und Datum werden nach erfolgreicher Paketerzeugung in derselben Transaktion aktualisiert.

`LastPktNum` wird stillgelegt. Zukünftige Paketkennungen müssen unabhängig und kollisionssicher erzeugt werden.

### Sitzungsstatus

`iStatus` ist ausschließlich Zustand der aktuellen Online-Sitzung. Er gehört zu einer `session_id`, wird nicht aus `users.data` migriert und darf keine Rolle oder Capability darstellen.

### Stillgelegte Kompatibilitätsfelder

Vierzehn Felder werden nicht nach PostgreSQL migriert. Sie bleiben im Legacy-Kompatibilitätsdatensatz null und dürfen ohne eine neue Quellanalyse und Architekturentscheidung nicht wieder aktiviert werden.

Stillgelegt sind:

`iLastFileGroup`, `iLastMsgGroup`, `LastPktNum`, `xChat`, `xFsMsged`, `xScreenLen`, `xHangUps`, `Paged`, `iTransferTime`, `CrtDef`, `Protocol`, `IEMSI`, `ieMNU`, `ieTAB`.

## Zugriffsbefund

Direkt verwendet werden nur:

`sComment`, `Email`, `iLastFileArea`, `iLastMsgArea`, `OLRext`, `OLRlast`, `iStatus`.

Ohne direkten Zugriff im aktuellen Quellbaum sind:

`iLastFileGroup`, `iLastMsgGroup`, `LastPktNum`, `xChat`, `xFsMsged`, `xScreenLen`, `xHangUps`, `Paged`, `iTransferTime`, `CrtDef`, `Protocol`, `IEMSI`, `ieMNU`, `ieTAB`.

Ein fehlender Direktzugriff bedeutet nicht automatisch, dass das Feld aus dem Binärformat entfernt werden darf. Solange `users.data` als Legacy-Kompatibilität existiert, bleiben Strukturgröße und Whole-Record-Verhalten separat zu berücksichtigen.

## Entscheidungsübersicht

| Feld | Kategorie | Zugriffe | Entscheidung | Autorität | Ziel |
|---|---|---:|---|---|---|
| `sComment` | `comment-mailbox` | 15 | `persistent` | PostgreSQL | `bbs_user_admin_notes (planned).note_text` |
| `Email` | `comment-mailbox` | 14 | `persistent` | PostgreSQL | `bbs_user_mailbox_settings (planned).private_mailbox_enabled` |
| `iLastFileArea` | `navigation-state` | 5 | `persistent` | PostgreSQL | `bbs_user_navigation_state (planned).last_file_area_id` |
| `iLastFileGroup` | `navigation-state` | 0 | `retired` | none | — |
| `iLastMsgArea` | `navigation-state` | 6 | `persistent` | PostgreSQL | `bbs_user_navigation_state (planned).last_message_area_id` |
| `iLastMsgGroup` | `navigation-state` | 0 | `retired` | none | — |
| `LastPktNum` | `offline-reader-state` | 0 | `retired` | none | — |
| `OLRext` | `offline-reader-state` | 7 | `persistent` | PostgreSQL | `bbs_user_offline_reader_state (planned).packet_extension_counter` |
| `OLRlast` | `offline-reader-state` | 3 | `persistent` | PostgreSQL | `bbs_user_offline_reader_state (planned).last_download_on` |
| `xChat` | `session-runtime` | 0 | `retired` | none | — |
| `xFsMsged` | `session-runtime` | 0 | `retired` | none | — |
| `xScreenLen` | `session-runtime` | 0 | `retired` | none | — |
| `xHangUps` | `session-runtime` | 0 | `retired` | none | — |
| `Paged` | `session-runtime` | 0 | `retired` | none | — |
| `iTransferTime` | `session-runtime` | 0 | `retired` | none | — |
| `iStatus` | `session-runtime` | 1 | `session-only` | runtime session | `bbs_sessions.activity_status_code` |
| `CrtDef` | `iemsi-compatibility` | 0 | `retired` | none | — |
| `Protocol` | `iemsi-compatibility` | 0 | `retired` | none | — |
| `IEMSI` | `iemsi-compatibility` | 0 | `retired` | none | — |
| `ieMNU` | `iemsi-compatibility` | 0 | `retired` | none | — |
| `ieTAB` | `iemsi-compatibility` | 0 | `retired` | none | — |

## Einzelentscheidungen

### `sComment`

- **Kategorie:** `comment-mailbox`
- **Direkte Zugriffe:** 15 (Lesen 9, Schreiben 3, Read-Write 0, Metadaten 3)
- **Betroffene Komponenten:** `fortytwo-auth,mbsebbs,mbsetup`
- **Legacy-Semantik:** Sysop-Kommentar zum Benutzer; während vorbereiteter Registrierungen zusätzlich als technischer Marker missbraucht
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_admin_notes (planned).note_text`
- **Migration:** Nur echte menschliche Kommentare importieren; bekannte FortyTwo-Registrierungsmarker vorher erkennen und aus Registrierungs- sowie Legacy-Binding-Tabellen ableiten
- **Schreibregel:** Nur privilegierte Sysop-Operation mit Audit; kein Login-, Sitzungs- oder Provisionierungswriter
- **Konsistenzregel:** Nach der Umstellung niemals für Identität, Autorisierung oder Registrierungszustand verwenden
- **Sicherheitsregel:** Privater administrativer Vermerk; nicht an Benutzerlisten, Doors, Dropfiles oder unprivilegierte APIs ausgeben

### `Email`

- **Kategorie:** `comment-mailbox`
- **Direkte Zugriffe:** 14 (Lesen 11, Schreiben 3, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** `fortytwo-auth,mbfido,mbsebbs,mbsetup`
- **Legacy-Semantik:** Boolescher Schalter für eine private interne MBSE-Mailbox; keine E-Mail-Adresse
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_mailbox_settings (planned).private_mailbox_enabled`
- **Migration:** Nur den Booleschen Mailboxzustand übernehmen; niemals eine Internetadresse oder Kontaktinformation daraus ableiten
- **Schreibregel:** Registrierungsstandard oder privilegierte Admin-Änderung; Änderung auditieren
- **Konsistenzregel:** Deaktivieren stoppt Provisionierung und Scan neuer privater Mailboxbereiche, löscht aber keine bestehenden Nachrichten
- **Sicherheitsregel:** Keine Wirkung auf Login, Rollen, SSH-Zugriff oder PostgreSQL-Identität

### `iLastFileArea`

- **Kategorie:** `navigation-state`
- **Direkte Zugriffe:** 5 (Lesen 2, Schreiben 3, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** `fortytwo-auth,mbsebbs`
- **Legacy-Semantik:** Zuletzt verwendete numerische Dateibereichsnummer und Wiedereinstiegspunkt der nächsten Sitzung
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_navigation_state (planned).last_file_area_id`
- **Migration:** Legacy-Bereichsnummer gegen den aktuellen Dateibereichsbestand auflösen; unbekannte oder gelöschte Bereiche auf den freigegebenen Standardbereich zurücksetzen
- **Schreibregel:** Bei erfolgreicher Auswahl eines zugänglichen Dateibereichs transaktional aktualisieren
- **Konsistenzregel:** Gespeicherte Navigation gewährt niemals Zugriff; beim Einstieg Berechtigung erneut prüfen
- **Sicherheitsregel:** Keine ungeprüfte Übernahme einer numerischen Legacy-ID als Autorisierungsentscheidung

### `iLastFileGroup`

- **Kategorie:** `navigation-state`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Historisch vorgesehene letzte Dateigruppennummer; im aktuellen Quellbaum ohne direkten Zugriff
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren; eine Gruppe bei Bedarf aus dem gültigen Dateibereich ableiten
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Ein neuer direkter Zugriff erfordert eine neue geprüfte Architekturentscheidung
- **Sicherheitsregel:** Darf keine Zugriffsgruppe oder Rolle abbilden

### `iLastMsgArea`

- **Kategorie:** `navigation-state`
- **Direkte Zugriffe:** 6 (Lesen 3, Schreiben 3, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** `fortytwo-auth,mbsebbs`
- **Legacy-Semantik:** Zuletzt verwendete numerische Nachrichtenbereichsnummer und Wiedereinstiegspunkt der nächsten Sitzung
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_navigation_state (planned).last_message_area_id`
- **Migration:** Legacy-Bereichsnummer gegen den aktuellen Nachrichtenbestand auflösen; unbekannte oder gelöschte Bereiche auf den freigegebenen Standardbereich zurücksetzen
- **Schreibregel:** Bei erfolgreicher Auswahl eines zugänglichen Nachrichtenbereichs transaktional aktualisieren
- **Konsistenzregel:** Gespeicherte Navigation gewährt niemals Zugriff; beim Einstieg Berechtigung erneut prüfen
- **Sicherheitsregel:** Keine ungeprüfte Übernahme einer numerischen Legacy-ID als Autorisierungsentscheidung

### `iLastMsgGroup`

- **Kategorie:** `navigation-state`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Historisch vorgesehene letzte Nachrichtengruppennummer; im aktuellen Quellbaum ohne direkten Zugriff
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren; eine Gruppe bei Bedarf aus dem gültigen Nachrichtenbereich ableiten
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Ein neuer direkter Zugriff erfordert eine neue geprüfte Architekturentscheidung
- **Sicherheitsregel:** Darf keine Zugriffsgruppe oder Rolle abbilden

### `LastPktNum`

- **Kategorie:** `offline-reader-state`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Historische tägliche Offline-Paketnummer; im aktuellen Quellbaum ohne direkten Zugriff
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Neue Paketkennungen werden unabhängig und kollisionssicher erzeugt
- **Sicherheitsregel:** Nicht als Sequenz-, Besitz- oder Replay-Schutz nutzen

### `OLRext`

- **Kategorie:** `offline-reader-state`
- **Direkte Zugriffe:** 7 (Lesen 3, Schreiben 3, Read-Write 1, Metadaten 0)
- **Betroffene Komponenten:** `mbsebbs,mbsetup`
- **Legacy-Semantik:** Persistenter Zähler für die Erweiterung beziehungsweise Benennung von Offline-Reader-Paketen
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_offline_reader_state (planned).packet_extension_counter`
- **Migration:** Nichtnegativen Legacy-Integer übernehmen; negative oder unplausible Werte kontrolliert auf null setzen und protokollieren
- **Schreibregel:** Nur beim erfolgreichen Erzeugen eines Offline-Pakets atomar erhöhen
- **Konsistenzregel:** Zähler und zugehöriges letztes Downloaddatum in derselben Transaktion aktualisieren
- **Sicherheitsregel:** Zähler ist keine Autorisierung und kein kryptografischer Replay-Schutz

### `OLRlast`

- **Kategorie:** `offline-reader-state`
- **Direkte Zugriffe:** 3 (Lesen 1, Schreiben 2, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** `mbsebbs,mbsetup`
- **Legacy-Semantik:** Datum des letzten erfolgreichen Offline-Reader-Downloads im Legacy-Datumsformat
- **Entscheidung:** `persistent`
- **Autorität:** PostgreSQL
- **PostgreSQL-Ziel:** `bbs_user_offline_reader_state (planned).last_download_on`
- **Migration:** Gültiges Legacy-Datum in DATE umwandeln; leere oder ungültige Werte als NULL übernehmen und protokollieren
- **Schreibregel:** Nur nach erfolgreicher Paketerzeugung beziehungsweise erfolgreicher Downloadbereitstellung setzen
- **Konsistenzregel:** Datum und Paket-Erweiterungszähler in derselben Transaktion aktualisieren
- **Sicherheitsregel:** Nicht als Loginzeitpunkt, Aktivitätsnachweis oder Berechtigungsgrenze verwenden

### `xChat`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutztes historisches Chat-Bit
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Keine Wiederbelebung ohne neue Quellanalyse
- **Sicherheitsregel:** Keine Chat- oder Sysop-Berechtigung daraus ableiten

### `xFsMsged`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutztes historisches Full-Screen-Editor-Bit
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Keine Wiederbelebung ohne neue Quellanalyse
- **Sicherheitsregel:** Keine Editor-Freigabe daraus ableiten

### `xScreenLen`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutzte historische Bildschirmhöhe
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Bildschirmgröße zukünftig aus der aktuellen Sitzung oder Terminalaushandlung beziehen
- **Sicherheitsregel:** Keine Terminalfähigkeit aus diesem Wert vertrauen

### `xHangUps`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutzter historischer Auflegezähler
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Verbindungsabbrüche ausschließlich über Sitzungs- und Auditereignisse erfassen
- **Sicherheitsregel:** Nicht für Sperren oder Throttling verwenden

### `Paged`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Historischer Tageszähler für Sysop-Paging; aktuell unbenutzt
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Ein zukünftiges Paging-System erhält eigene Ereignisse und Ratelimits
- **Sicherheitsregel:** Nicht als Missbrauchs- oder Sperrindikator verwenden

### `iTransferTime`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Historisch vorgesehene Dauer der letzten Dateiübertragung; aktuell unbenutzt
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Übertragungszeiten zukünftig als Ereignismetrik und nicht im Benutzerdatensatz erfassen
- **Sicherheitsregel:** Keine Downloadberechtigung daraus ableiten

### `iStatus`

- **Kategorie:** `session-runtime`
- **Direkte Zugriffe:** 1 (Lesen 0, Schreiben 1, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** `mbsebbs`
- **Legacy-Semantik:** WhosDoingWhat-Aktivitätscode der aktuellen Online-Sitzung
- **Entscheidung:** `session-only`
- **Autorität:** runtime session
- **PostgreSQL-Ziel:** `bbs_sessions.activity_status_code`
- **Migration:** Keinen Bestandswert aus users.data übernehmen; jede Sitzung beginnt mit einem definierten neutralen Status
- **Schreibregel:** Nur durch die aktive Sitzung ändern; bei Sitzungsende verwerfen oder als Auditereignis abschließen
- **Konsistenzregel:** Status gehört eindeutig zu einer session_id und niemals als dauerhafte Benutzerpräferenz zum Benutzerkonto
- **Sicherheitsregel:** Anzeigeinformation; keine Rolle, Capability oder Autorisierungsentscheidung

### `CrtDef`

- **Kategorie:** `iemsi-compatibility`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutzte historische IEMSI-Terminalemulation
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Terminaltyp ausschließlich aus moderner Sitzungsaushandlung bestimmen
- **Sicherheitsregel:** Keine Terminalfähigkeit ungeprüft übernehmen

### `Protocol`

- **Kategorie:** `iemsi-compatibility`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutzter numerischer IEMSI-Protokollwert; nicht das aktive Textfeld sProtocol
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Nicht mit der bereits entschiedenen Übertragungspräferenz sProtocol vermischen
- **Sicherheitsregel:** Keine Protokollfreigabe daraus ableiten

### `IEMSI`

- **Kategorie:** `iemsi-compatibility`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutztes historisches IEMSI-Sitzungsbit
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Keine Wiederbelebung ohne neue Protokollentscheidung
- **Sicherheitsregel:** Keiner vom Client behaupteten Fähigkeit vertrauen

### `ieMNU`

- **Kategorie:** `iemsi-compatibility`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutztes historisches IEMSI-Bit für ASCII-Menüdownloads
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** Keine Wiederbelebung ohne neue Quellanalyse
- **Sicherheitsregel:** Keine Downloadfähigkeit daraus ableiten

### `ieTAB`

- **Kategorie:** `iemsi-compatibility`
- **Direkte Zugriffe:** 0 (Lesen 0, Schreiben 0, Read-Write 0, Metadaten 0)
- **Betroffene Komponenten:** keine direkten Zugriffe
- **Legacy-Semantik:** Unbenutztes historisches IEMSI-Bit für TAB-Unterstützung
- **Entscheidung:** `retired`
- **Autorität:** none
- **PostgreSQL-Ziel:** keines
- **Migration:** Nicht importieren
- **Schreibregel:** Im Legacy-Kompatibilitätsdatensatz auf null belassen
- **Konsistenzregel:** TAB-Verhalten aus der aktuellen Terminaldarstellung bestimmen
- **Sicherheitsregel:** Keine Terminalfähigkeit ungeprüft übernehmen

## Reproduzierbarkeit

Die Dokumentation wird ausschließlich aus folgenden versionierten Quellen erzeugt:

- `docs/NAVIGATION_SESSION_ACCESS_RAW.tsv`
- `docs/NAVIGATION_SESSION_ACCESS_DETAILS.tsv`
- `docs/NAVIGATION_SESSION_OWNERSHIP_DECISIONS.tsv`
- `docs/MBSETUP_USER_FIELD_OWNERSHIP_DETAILS.tsv`
- `scripts/analyze_navigation_session_access.py`
- `scripts/build_navigation_session_ownership.py`

Der Builder akzeptiert nur den geprüften Restbestand von 21 Feldern, exakt 51 direkte Fundstellen sowie die Entscheidungsverteilung 6 persistent, 1 session-only und 14 retired.
