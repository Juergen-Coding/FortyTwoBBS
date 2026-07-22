# FortyTwo BBS – B5.9 Aktivität, Zeitkonten und Nutzungsstatistik

**Stand:** 22. Juli 2026

**Phase:** B5.9 – Aktivität, Zeitkonten und Nutzungsstatistik

## 1. Ergebnis

Für alle 15 untersuchten Aktivitäts-, Zeitkonto- und Nutzungsfelder ist die künftige Behandlung entschieden.

```text
Kontohistorie:                       2
Zeitkonten:                          3
Legacy-Kompatibilitätswert:          1
Transfer- und Quotawerte:            7
Zugriffs- und Beitragszähler:        2
dauerhafte PostgreSQL-Entscheidungen: 12
abgeleitete Werte:                    2
reine Sitzungswerte:                  1
offene B5.9-Entscheidungen:            0
geprüfte Direktzugriffe:              126
```

`iTimeLeft` und `DownloadsToday` sind keine eigenständigen Benutzerkontostände, sondern aus Richtlinie und Verbrauch abzuleitende Werte.

`iConnectTime` gehört ausschließlich zur aktiven Sitzung.

## 2. Zentrale Altcodebefunde

- `tFirstLoginDate` enthält tatsächlich den Registrierungszeitpunkt.
- `tLastLoginDate` und `iTotalCalls` werden sowohl bei BBS- als auch bei NNTP-Zugriffen verändert.
- Die Zeitfelder verwenden Minuten. Der Legacy-Wert `86400` für 24 Stunden ist deshalb fehlerhaft; korrekt wären 1440 Minuten.
- `DownloadsToday` ist als verbleibende Dateiquote gedacht, wird aber weder geprüft noch vermindert.
- `DownloadKToday` ist ein veränderlicher Tageskontosaldo: Downloads belasten ihn, Uploads können ihn erhöhen.
- `Credit` bezeichnet ausschließlich Blue-Wave-NetMail-Credits und keine allgemeine BBS-Währung.

## 3. Entscheidungsübersicht

| Feld | Kategorie | Status | Führung | Ziel | Lesen | Schreiben | Dateien |
|---|---|---|---|---|---:|---:|---:|
| `tFirstLoginDate` | account-timeline | decided | PostgreSQL | `bbs_users.registered_at` | 5 | 2 | 5 |
| `tLastLoginDate` | account-timeline | decided | PostgreSQL | `bbs_user_access_summary.last_successful_access_at (planned)` | 11 | 4 | 8 |
| `iTimeLeft` | time-account | derived | Derived | `derived: bbs_access_policies.daily_online_seconds - bbs_user_daily_usage.online_seconds_used (planned)` | 18 | 8 | 9 |
| `iTimeUsed` | time-account | decided | PostgreSQL | `bbs_user_daily_usage.online_seconds_used (planned)` | 4 | 4 | 5 |
| `iConnectTime` | session-state | session-only | PostgreSQL session state | `bbs_sessions.connected_seconds (planned)` | 3 | 3 | 5 |
| `Credit` | offline-reader-compatibility | decided | PostgreSQL | `bbs_user_offline_reader_settings.netmail_credits (planned)` | 3 | 1 | 2 |
| `Downloads` | transfer-usage | decided | PostgreSQL | `bbs_user_usage_totals.download_files (planned)` | 7 | 2 | 4 |
| `Uploads` | transfer-usage | decided | PostgreSQL | `bbs_user_usage_totals.upload_files (planned)` | 5 | 2 | 5 |
| `DownloadK` | transfer-usage | decided | PostgreSQL | `bbs_user_usage_totals.download_bytes (planned)` | 5 | 1 | 4 |
| `UploadK` | transfer-usage | decided | PostgreSQL | `bbs_user_usage_totals.upload_bytes (planned)` | 6 | 1 | 4 |
| `DownloadsToday` | transfer-policy-derived | derived | Derived | `derived: bbs_access_policies.daily_download_file_limit (planned)` | 1 | 1 | 2 |
| `DownloadKToday` | daily-transfer-quota | decided | PostgreSQL | `bbs_user_daily_usage.download_balance_bytes (planned)` | 4 | 3 | 3 |
| `UploadKToday` | daily-transfer-usage | decided | PostgreSQL | `bbs_user_daily_usage.upload_bytes (planned)` | 1 | 1 | 1 |
| `iTotalCalls` | community-usage | decided | PostgreSQL | `bbs_user_access_summary.successful_access_count (planned)` | 9 | 2 | 8 |
| `iPosted` | community-usage | decided | PostgreSQL | `bbs_user_usage_totals.messages_posted (planned)` | 4 | 5 | 7 |

## 4. Einzelentscheidungen

### `tFirstLoginDate`

**Legacy-Semantik:** Tatsächlicher Registrierungszeitpunkt; der Feldname first login ist irreführend

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_users.registered_at`

**Einheitenregel:** Legacy-Epochsekunden werden als timestamptz interpretiert

**Migrationsregel:** Gültigen Legacy-Wert übernehmen; bei Abweichung besitzt der FTAP-Registrierungszeitpunkt Vorrang

**Schreibregel:** Nur der erfolgreiche Registrierungsprozess darf den Wert einmalig setzen

**Konsistenzregel:** Nach erfolgreicher Registrierung unveränderlich; administrative Korrekturen nur auditiert

**Legacy-Kompatibilität:** Legacy-Feld aus registered_at ableiten

### `tLastLoginDate`

**Legacy-Semantik:** Zeitpunkt des letzten erfolgreichen BBS- oder NNTP-Zugriffs

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_access_summary.last_successful_access_at (planned)`

**Einheitenregel:** Legacy-Epochsekunden werden als timestamptz interpretiert

**Migrationsregel:** Nur positive und plausible Werte übernehmen; Null bedeutet noch kein erfolgreicher Zugriff

**Schreibregel:** Nur nach vollständig erfolgreicher Authentifizierung und Autorisierung aktualisieren

**Konsistenzregel:** Zugriffsereignis und Zusammenfassung werden in derselben Transaktion geschrieben; fehlgeschlagene Anmeldungen zählen nicht

**Legacy-Kompatibilität:** Legacy-Feld aus der transportübergreifenden Zugriffszusammenfassung ableiten

### `iTimeLeft`

**Legacy-Semantik:** Verbleibendes tägliches Online-Zeitbudget in Minuten

**Führung:** Derived

**PostgreSQL-Ziel:** `derived: bbs_access_policies.daily_online_seconds - bbs_user_daily_usage.online_seconds_used (planned)`

**Einheitenregel:** Legacy-Minuten werden für Berechnungen mit 60 in Sekunden umgerechnet

**Migrationsregel:** Nicht als unabhängigen Saldo migrieren; nur mit iTimeUsed und der geprüften Tagesrichtlinie abgleichen

**Schreibregel:** Darf nicht direkt geschrieben werden; der Wert wird aus Richtlinie und Tagesverbrauch berechnet

**Konsistenzregel:** Unbegrenzt wird als NULL-Richtlinie modelliert; niemals als magische Zahl 86400 Minuten

**Legacy-Kompatibilität:** Für Legacy-Code aus dem Restbudget in Minuten ableiten; bei unbegrenzt höchstens 1440 Minuten pro Sitzung ausgeben

### `iTimeUsed`

**Legacy-Semantik:** Heute verbrauchte Online-Zeit in Minuten

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_daily_usage.online_seconds_used (planned)`

**Einheitenregel:** Legacy-Minuten werden mit 60 in Sekunden umgerechnet

**Migrationsregel:** Wert dem Installationstag des Legacy-Datensatzes zuordnen; negative Werte ablehnen

**Schreibregel:** Nur durch atomare Sitzungsabrechnung erhöhen; administrative Korrekturen benötigen Auditgrund

**Konsistenzregel:** Tageswerte sind nach Benutzer und Installationstag getrennt; kein Reset durch Überschreiben des Benutzerprofils

**Legacy-Kompatibilität:** Legacy-Minuten aus den gespeicherten Sekunden ableiten

### `iConnectTime`

**Legacy-Semantik:** Online-Zeit der aktuellen Sitzung in Minuten

**Führung:** PostgreSQL session state

**PostgreSQL-Ziel:** `bbs_sessions.connected_seconds (planned)`

**Einheitenregel:** Legacy-Minuten werden mit 60 in Sekunden umgerechnet

**Migrationsregel:** Alte Datensatzwerte nicht migrieren, da sie beim Login ohnehin auf null gesetzt werden

**Schreibregel:** Nur die aktive Sitzung darf den Wert monoton aktualisieren

**Konsistenzregel:** Kein dauerhafter Benutzerprofilwert; Sitzungsende schreibt die endgültige Dauer atomar

**Legacy-Kompatibilität:** Beim Aufbau eines Legacy-Sitzungsdatensatzes zunächst null, danach aus der aktiven Sitzung ableiten

### `Credit`

**Legacy-Semantik:** Blue-Wave-NetMail-Credits; keine allgemeine BBS-Währung

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_offline_reader_settings.netmail_credits (planned)`

**Einheitenregel:** Ganzzahl im Bereich 0 bis 65535 für das Blue-Wave-tWORD-Feld

**Migrationsregel:** Nur gültige Werte übernehmen; negative oder übergroße Werte zur manuellen Prüfung markieren und niemals umbrechen

**Schreibregel:** Nur administrativ und auditiert änderbar

**Konsistenzregel:** Keine Verwendung für Login, Rollen, Downloads oder andere Kontoberechtigungen

**Legacy-Kompatibilität:** Nur bei aktivierter Blue-Wave-Ausgabe exportieren; Debits bleiben getrennt und standardmäßig null

### `Downloads`

**Legacy-Semantik:** Kumulative Anzahl erfolgreich abgeschlossener Datei-Downloads

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_usage_totals.download_files (planned)`

**Einheitenregel:** Nichtnegative BIGINT-Anzahl

**Migrationsregel:** Nichtnegative Legacy-Anzahl übernehmen

**Schreibregel:** Nur nach erfolgreichem Abschluss atomar erhöhen; administrative Korrekturen nur als auditierte Anpassung

**Konsistenzregel:** Keine Ganzsatz-Rewrites und keine verlorenen Updates bei parallelen Übertragungen

**Legacy-Kompatibilität:** Legacy-Feld aus dem kumulativen Zähler ableiten

### `Uploads`

**Legacy-Semantik:** Kumulative Anzahl erfolgreich abgeschlossener Datei-Uploads

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_usage_totals.upload_files (planned)`

**Einheitenregel:** Nichtnegative BIGINT-Anzahl

**Migrationsregel:** Nichtnegative Legacy-Anzahl übernehmen

**Schreibregel:** Nur nach erfolgreichem Abschluss atomar erhöhen; administrative Korrekturen nur als auditierte Anpassung

**Konsistenzregel:** Keine Ganzsatz-Rewrites und keine verlorenen Updates bei parallelen Übertragungen

**Legacy-Kompatibilität:** Legacy-Feld aus dem kumulativen Zähler ableiten

### `DownloadK`

**Legacy-Semantik:** Kumulative heruntergeladene Datenmenge, trotz irreführendem Altcodekommentar nicht nur heute

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_usage_totals.download_bytes (planned)`

**Einheitenregel:** Legacy-KiB werden mit 1024 in Bytes umgerechnet

**Migrationsregel:** Nichtnegative Legacy-KiB übernehmen; Überlauf oder negative Werte zur Prüfung markieren

**Schreibregel:** Erfolgreich übertragene Bytes atomar addieren

**Konsistenzregel:** Der Dateizähler und die Bytezahl werden im selben Übertragungsabschluss aktualisiert

**Legacy-Kompatibilität:** Legacy-KiB durch ganzzahlige Division der Bytes durch 1024 ableiten

### `UploadK`

**Legacy-Semantik:** Kumulative hochgeladene Datenmenge

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_usage_totals.upload_bytes (planned)`

**Einheitenregel:** Legacy-KiB werden mit 1024 in Bytes umgerechnet

**Migrationsregel:** Nichtnegative Legacy-KiB übernehmen; Überlauf oder negative Werte zur Prüfung markieren

**Schreibregel:** Erfolgreich übertragene Bytes atomar addieren

**Konsistenzregel:** Der Dateizähler und die Bytezahl werden im selben Übertragungsabschluss aktualisiert

**Legacy-Kompatibilität:** Legacy-KiB durch ganzzahlige Division der Bytes durch 1024 ableiten

### `DownloadsToday`

**Legacy-Semantik:** Vorgesehene verbleibende Dateidownloads des Tages; im Altcode weder geprüft noch vermindert

**Führung:** Derived

**PostgreSQL-Ziel:** `derived: bbs_access_policies.daily_download_file_limit (planned)`

**Einheitenregel:** Nichtnegative Anzahl oder NULL für kein Dateilimit

**Migrationsregel:** Keinen Legacy-Benutzerwert migrieren, weil er nur beim Tageswechsel auf LIMIT.DownF gesetzt wird

**Schreibregel:** Kein direkt schreibbarer Benutzerzustand; eine künftige Dateiquote benötigt eine neue vollständige Implementierung

**Konsistenzregel:** Die bestehende unvollständige Durchsetzung darf nicht als funktionierende Sicherheitsgrenze gelten

**Legacy-Kompatibilität:** Solange keine neue Dateiquote existiert, für Doors aus der aktuellen Richtlinie oder als null ableiten

### `DownloadKToday`

**Legacy-Semantik:** Verbleibendes tägliches Download-Kontingent; Downloads vermindern, Uploads erhöhen den Saldo

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_daily_usage.download_balance_bytes (planned)`

**Einheitenregel:** Legacy-KiB werden mit 1024 in Bytes umgerechnet

**Migrationsregel:** Aktuellen nichtnegativen Saldo dem Installationstag zuordnen; negative Altwerte zur Prüfung markieren

**Schreibregel:** Downloads vermindern und freigegebene Upload-Boni erhöhen den Saldo atomar

**Konsistenzregel:** Tagesrichtlinie, Downloadabbuchung und Uploadgutschrift müssen explizit getrennt und transaktionssicher sein

**Legacy-Kompatibilität:** Legacy-KiB aus dem Tageskontosaldo ableiten

### `UploadKToday`

**Legacy-Semantik:** Heute erfolgreich hochgeladene Datenmenge

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_daily_usage.upload_bytes (planned)`

**Einheitenregel:** Legacy-KiB werden mit 1024 in Bytes umgerechnet

**Migrationsregel:** Nichtnegativen Legacy-Wert dem Installationstag zuordnen

**Schreibregel:** Nach erfolgreichem Upload atomar erhöhen

**Konsistenzregel:** Tageswechsel erfolgt über einen neuen datumsgebundenen Datensatz und nicht durch Profilüberschreibung

**Legacy-Kompatibilität:** Legacy-KiB aus der heutigen Bytemenge ableiten

### `iTotalCalls`

**Legacy-Semantik:** Anzahl erfolgreicher Zugriffe; der Altcode zählt BBS- und NNTP-Anmeldungen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_access_summary.successful_access_count (planned)`

**Einheitenregel:** Nichtnegative BIGINT-Anzahl

**Migrationsregel:** Nichtnegative Legacy-Anzahl als Anfangswert übernehmen

**Schreibregel:** Nur bei erfolgreichem, ausdrücklich zählendem Zugriff atomar erhöhen

**Konsistenzregel:** Zeitpunkt, Transport und Zählerfortschreibung müssen aus demselben erfolgreichen Zugriffsereignis entstehen

**Legacy-Kompatibilität:** Legacy-Feld aus dem transportübergreifenden Zugriffszähler ableiten

### `iPosted`

**Legacy-Semantik:** Kumulative Anzahl akzeptierter Nachrichten aus BBS, Offline-Import und NNTP

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_usage_totals.messages_posted (planned)`

**Einheitenregel:** Nichtnegative BIGINT-Anzahl

**Migrationsregel:** Nichtnegative Legacy-Anzahl übernehmen

**Schreibregel:** Nur nach erfolgreicher Nachrichtenannahme atomar erhöhen

**Konsistenzregel:** Nachricht und Zählerfortschreibung müssen gemeinsam committen; abgewiesene oder zurückgerollte Nachrichten zählen nicht

**Legacy-Kompatibilität:** Legacy-Feld aus dem kumulativen Beitragszähler ableiten

## 5. Konsequenzen für die Umsetzung

1. Kumulative Zähler werden atomar erhöht und niemals über Ganzsatz-Rewrites aus `users.data` zurückgeschrieben.
2. Tageswerte werden nach Benutzer und Installationstag gespeichert; ein Tageswechsel erzeugt einen neuen Zustand.
3. Zeit- und Transferkontingente werden getrennt von Verbrauch, Gutschriften und kumulativer Statistik modelliert.
4. Erfolgreiche Zugriffe und Nachrichtenannahmen erzeugen Ereignis und Zählerfortschreibung in derselben Transaktion.
5. `mbsetup` darf Statistik-, Tages- und Sitzungswerte nicht durch Bearbeitung eines vollständigen Legacy-Datensatzes ändern.
6. Die unvollständige Legacy-Dateiquote wird nicht als bestehende Sicherheitsgrenze übernommen.
