# FortyTwo BBS – B5.8 Profil- und Terminalpräferenzen

**Stand:** 22. Juli 2026

**Phase:** B5.8 – Profil- und Terminalpräferenzen

## 1. Ergebnis

Für alle 24 untersuchten Profil- und Terminalfelder ist die künftige Behandlung entschieden.

```text
Profilfelder:                         9
Terminal- und Bedienpräferenzen:      15
beibehaltene PostgreSQL-Entscheidungen: 3
neue PostgreSQL-Entscheidungen:          18
stillgelegte Legacy-Felder:              3
offene B5.8-Entscheidungen:             0
geprüfte Direktzugriffe:                 464
```

Die aktiven Felder werden PostgreSQL-geführt. `Cls`, `More` und `ieASCII8` werden nicht migriert, weil der untersuchte Laufzeitcode ihre Werte nicht auswertet.

## 2. Datenschutzgrenze

Telefonnummern, Anschrift, Geburtsdatum und Geschlechtsangabe sind private Profildaten.

Diese Werte dürfen weder im Klartext protokolliert noch standardmäßig an Doors, Benutzerlisten oder andere Legacy-Schnittstellen weitergegeben werden.

Der öffentliche Standorttext bleibt davon getrennt. Seine Ausgabe richtet sich nach einer ausdrücklich festgelegten Sichtbarkeitspolitik.

## 3. Entscheidungsübersicht

| Feld | Kategorie | Status | Führung | PostgreSQL-Ziel | Lesen | Schreiben | Dateien |
|---|---|---|---|---|---:|---:|---:|
| `sUserName` | profile-identity | retained | PostgreSQL | `bbs_user_profiles.display_name` | 95 | 8 | 27 |
| `sHandle` | profile-identity | retained | PostgreSQL | `bbs_user_profiles.handle` | 46 | 7 | 15 |
| `iLanguage` | profile-preference | retained | PostgreSQL | `bbs_user_profiles.language_code` | 4 | 4 | 6 |
| `sVoicePhone` | private-profile | decided | PostgreSQL | `bbs_user_private_profiles.voice_phone (planned)` | 10 | 4 | 5 |
| `sDataPhone` | private-profile | decided | PostgreSQL | `bbs_user_private_profiles.data_phone (planned)` | 9 | 5 | 5 |
| `sLocation` | public-profile | decided | PostgreSQL | `bbs_user_profiles.location_text (planned)` | 15 | 5 | 10 |
| `address` | private-profile | decided | PostgreSQL | `bbs_user_private_profiles.postal_address_lines (planned)` | 25 | 3 | 4 |
| `sDateOfBirth` | private-profile | decided | PostgreSQL | `bbs_user_private_profiles.date_of_birth (planned)` | 9 | 5 | 6 |
| `sSex` | private-profile | decided | PostgreSQL | `bbs_user_private_profiles.sex_code (planned)` | 5 | 7 | 3 |
| `HotKeys` | terminal-preference | decided | PostgreSQL | `bbs_user_preferences.hotkeys_enabled (planned)` | 7 | 7 | 7 |
| `GraphMode` | terminal-preference | decided | PostgreSQL | `bbs_user_preferences.ansi_enabled (planned)` | 20 | 7 | 9 |
| `DoNotDisturb` | terminal-preference | decided | PostgreSQL | `bbs_user_preferences.do_not_disturb (planned)` | 7 | 4 | 5 |
| `Cls` | retired-preference | retired | Retired | keine Speicherung | 2 | 3 | 3 |
| `More` | retired-preference | retired | Retired | keine Speicherung | 2 | 3 | 3 |
| `MailScan` | login-preference | decided | PostgreSQL | `bbs_user_preferences.scan_new_mail (planned)` | 6 | 8 | 6 |
| `OL_ExtInfo` | offline-reader-preference | decided | PostgreSQL | `bbs_user_preferences.offline_extended_info (planned)` | 8 | 3 | 4 |
| `MsgEditor` | editor-preference | decided | PostgreSQL | `bbs_user_preferences.message_editor (planned)` | 7 | 9 | 7 |
| `Archiver` | offline-reader-preference | decided | PostgreSQL | `bbs_user_preferences.archive_format (planned)` | 10 | 6 | 5 |
| `sProtocol` | transfer-preference | decided | PostgreSQL | `bbs_user_preferences.transfer_protocol (planned)` | 6 | 6 | 7 |
| `ieASCII8` | retired-preference | retired | Retired | keine Speicherung | 0 | 2 | 2 |
| `ieNEWS` | login-preference | decided | PostgreSQL | `bbs_user_preferences.show_news_on_login (planned)` | 6 | 5 | 6 |
| `ieFILE` | login-preference | decided | PostgreSQL | `bbs_user_preferences.show_new_files_on_login (planned)` | 6 | 8 | 6 |
| `FSemacs` | editor-preference | decided | PostgreSQL | `bbs_user_preferences.fs_editor_keymap (planned)` | 6 | 3 | 4 |
| `Charset` | terminal-preference | decided | PostgreSQL | `bbs_user_preferences.character_set (planned)` | 21 | 3 | 9 |

## 4. Einzelentscheidungen

### `sUserName`

**Legacy-Semantik:** Anzeigename des Benutzers

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_profiles.display_name`

**Migrationsregel:** Bestehende B5.4-Zuordnung unverändert übernehmen

**Schreibregel:** Änderung nur über die kontrollierte Profilfunktion

**Datenschutz:** In Benutzeroberflächen sichtbar; keine unnötige Protokollierung

**Legacy-Kompatibilität:** Bei Bedarf in den Legacy-Datensatz spiegeln

### `sHandle`

**Legacy-Semantik:** Öffentlicher Alias oder Handle

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_profiles.handle`

**Migrationsregel:** Bestehende B5.4-Zuordnung unverändert übernehmen

**Schreibregel:** Änderung nur über die kontrollierte Profilfunktion mit Eindeutigkeitsprüfung

**Datenschutz:** Öffentliches Profilfeld

**Legacy-Kompatibilität:** Bei Bedarf in den Legacy-Datensatz spiegeln

### `iLanguage`

**Legacy-Semantik:** Bevorzugte BBS-Sprache

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_profiles.language_code`

**Migrationsregel:** Legacy-Sprachindex in einen stabilen Sprachcode übersetzen

**Schreibregel:** Benutzer darf seine verfügbare Sprache selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Index nur aus dem PostgreSQL-Sprachcode ableiten

### `sVoicePhone`

**Legacy-Semantik:** Primäre Telefonnummer

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_private_profiles.voice_phone (planned)`

**Migrationsregel:** Leerwert wird NULL; Nummer normalisieren, ohne nicht normierbare Legacy-Werte zu verlieren

**Schreibregel:** Selbstverwaltung nur wenn die Installation das Feld aktiviert; administrativer Zugriff möglich

**Datenschutz:** Privat; niemals im Klartext protokollieren oder standardmäßig an Doors exportieren

**Legacy-Kompatibilität:** Nur für ausdrücklich freigegebene Legacy-Kompatibilität spiegeln

### `sDataPhone`

**Legacy-Semantik:** Historische Daten- oder geschäftliche Telefonnummer

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_private_profiles.data_phone (planned)`

**Migrationsregel:** Leerwert wird NULL; identischen Wert zur Voice-Nummer nicht künstlich duplizieren

**Schreibregel:** Selbstverwaltung nur wenn die Installation das Feld aktiviert; administrativer Zugriff möglich

**Datenschutz:** Privat; niemals im Klartext protokollieren oder standardmäßig an Doors exportieren

**Legacy-Kompatibilität:** Nur für ausdrücklich freigegebene Legacy-Kompatibilität spiegeln

### `sLocation`

**Legacy-Semantik:** Vom Benutzer angegebener Ort oder Standorttext

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_profiles.location_text (planned)`

**Migrationsregel:** Text unverändert erhalten, lediglich Länge und UTF-8 validieren

**Schreibregel:** Benutzer darf den eigenen Standorttext bearbeiten

**Datenschutz:** Profilfeld; Ausgabe in Listen und an Doors nur nach festgelegter Sichtbarkeitspolitik

**Legacy-Kompatibilität:** Für kompatible Benutzerlisten und freigegebene Doors ableitbar

### `address`

**Legacy-Semantik:** Postanschrift mit bis zu drei Legacy-Zeilen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_private_profiles.postal_address_lines (planned)`

**Migrationsregel:** Drei Legacy-Zeilen geordnet übernehmen; vollständig leere Anschrift wird NULL

**Schreibregel:** Selbstverwaltung nur wenn die Installation die Anschrift verlangt; administrativer Zugriff möglich

**Datenschutz:** Streng privat und standardmäßig nur administrativ sichtbar; niemals im Klartext protokollieren

**Legacy-Kompatibilität:** Nicht an Doors oder öffentliche Benutzerlisten ausgeben

### `sDateOfBirth`

**Legacy-Semantik:** Geburtsdatum für Altersprüfung und Geburtstagsanzeige

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_private_profiles.date_of_birth (planned)`

**Migrationsregel:** Gültiges DD-MM-YYYY in PostgreSQL DATE konvertieren; ungültige Werte nicht stillschweigend übernehmen

**Schreibregel:** Selbstverwaltung nur über validierte Datumseingabe; administrativer Zugriff möglich

**Datenschutz:** Privat; keine Klartext-Protokollierung und kein standardmäßiger Door-Export

**Legacy-Kompatibilität:** Geburtstagsfunktion darf nur Tag und Monat auswerten

### `sSex`

**Legacy-Semantik:** Historische Auswahl Male, Female oder Unknown

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_private_profiles.sex_code (planned)`

**Migrationsregel:** Male, Female und Unknown in geprüfte kanonische Werte übersetzen; sonst NULL

**Schreibregel:** Optionales selbstverwaltetes Profilfeld; ohne Einfluss auf Berechtigungen

**Datenschutz:** Privat; keine Klartext-Protokollierung und keine Verwendung für Autorisierung oder automatische Entscheidungen

**Legacy-Kompatibilität:** Nur bei ausdrücklichem Legacy-Bedarf spiegeln

### `HotKeys`

**Legacy-Semantik:** Ein-Tasten-Menüauswahl

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.hotkeys_enabled (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `GraphMode`

**Legacy-Semantik:** ANSI-Farben und ANSI-Terminalausgabe

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.ansi_enabled (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern; Transporterkennung darf nur einen Sitzungswert vorschlagen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `DoNotDisturb`

**Legacy-Semantik:** Dauerhafte Nicht-stören-Vorgabe

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.do_not_disturb (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Vorgabe selbst ändern; bei Sitzungsbeginn auf den Laufzeitstatus anwenden

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `Cls`

**Legacy-Semantik:** Historische Clear-Screen-Präferenz ohne Laufzeitleser

**Führung:** Retired

**PostgreSQL-Ziel:** keine Speicherung

**Migrationsregel:** Nicht nach PostgreSQL migrieren

**Schreibregel:** Nicht mehr bearbeitbar

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Für Legacy-Datensätze festen Wert true ausgeben, solange das Binärformat fortbesteht

### `More`

**Legacy-Semantik:** Historische More-Prompt-Präferenz ohne Laufzeitleser

**Führung:** Retired

**PostgreSQL-Ziel:** keine Speicherung

**Migrationsregel:** Nicht nach PostgreSQL migrieren

**Schreibregel:** Nicht mehr bearbeitbar

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Für Legacy-Datensätze festen Wert true ausgeben, solange das Binärformat fortbesteht

### `MailScan`

**Legacy-Semantik:** Automatische Suche nach neuer Mail beim Login

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.scan_new_mail (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `OL_ExtInfo`

**Legacy-Semantik:** Erweiterte Nachrichteninformationen in Offline-Paketen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.offline_extended_info (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `MsgEditor`

**Legacy-Semantik:** Bevorzugter Nachrichteneditor

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.message_editor (planned)`

**Migrationsregel:** Legacy-Konstante in einen stabilen Editorbezeichner übersetzen

**Schreibregel:** Benutzer darf einen verfügbaren Editor selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Konstante nur aus dem PostgreSQL-Bezeichner ableiten

### `Archiver`

**Legacy-Semantik:** Bevorzugtes Archivformat für Offline-Pakete

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.archive_format (planned)`

**Migrationsregel:** Archivnamen normalisieren; leerer Legacy-Wert wird als ZIP interpretiert

**Schreibregel:** Benutzer darf ein verfügbares Archivformat selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Nur ein aktuell verfügbares Legacy-Archivformat ausgeben

### `sProtocol`

**Legacy-Semantik:** Bevorzugtes Dateiübertragungsprotokoll

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.transfer_protocol (planned)`

**Migrationsregel:** Anzeigenamen in einen stabilen Protokollbezeichner übersetzen

**Schreibregel:** Benutzer darf ein aktuell verfügbares Protokoll selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Anzeigenamen aus dem stabilen Bezeichner ableiten

### `ieASCII8`

**Legacy-Semantik:** Historisches IEMSI-ASCII8-Merkmal ohne Laufzeitleser

**Führung:** Retired

**PostgreSQL-Ziel:** keine Speicherung

**Migrationsregel:** Nicht nach PostgreSQL migrieren

**Schreibregel:** Nicht mehr bearbeitbar

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Für Legacy-Datensätze festen Wert true ausgeben, solange das Binärformat fortbesteht

### `ieNEWS`

**Legacy-Semantik:** News-Bulletins beim Login anzeigen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.show_news_on_login (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `ieFILE`

**Legacy-Semantik:** Neue Dateien beim Login anzeigen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.show_new_files_on_login (planned)`

**Migrationsregel:** Legacy-Booleschen Wert unverändert übernehmen

**Schreibregel:** Benutzer darf die Präferenz selbst ändern

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus PostgreSQL ableiten

### `FSemacs`

**Legacy-Semantik:** Emacs- oder WordStar-Tastenbelegung im Fullscreen-Editor

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.fs_editor_keymap (planned)`

**Migrationsregel:** Booleschen Legacy-Wert in emacs oder wordstar übersetzen

**Schreibregel:** Benutzer darf die Tastenbelegung selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Booleschen Wert aus dem kanonischen Bezeichner ableiten

### `Charset`

**Legacy-Semantik:** Zeichensatz für Terminal, Nachrichten und NNTP

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_preferences.character_set (planned)`

**Migrationsregel:** Legacy-Enum in einen kanonischen Zeichensatzbezeichner übersetzen

**Schreibregel:** Benutzer darf einen unterstützten Zeichensatz selbst wählen

**Datenschutz:** Nicht sensibel

**Legacy-Kompatibilität:** Legacy-Enum nur aus einem unterstützten PostgreSQL-Wert ableiten

## 5. Konsequenzen für die Umsetzung

1. Aktive Profil- und Präferenzwerte werden aus PostgreSQL gelesen und über kontrollierte Funktionen geändert.
2. Transporterkennung darf dauerhafte Präferenzen nur vorschlagen, nicht ungefragt überschreiben.
3. Private Profildaten werden von öffentlichem Profil, Berechtigungen und Sitzungszustand getrennt.
4. Legacy-Door-Exporte erhalten private Daten nur nach ausdrücklicher Freigabe und minimalem Datenprinzip.
5. `mbsetup` darf PostgreSQL-geführte Werte nicht durch Ganzsatz-Rewrites aus `users.data` zurücksetzen.
6. Stillgelegte Felder erhalten höchstens feste Kompatibilitätswerte, solange das Legacy-Binärformat besteht.
