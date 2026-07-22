# FortyTwo BBS – B5.7 Kontolebenszyklus, Sperren und Sichtbarkeit

**Stand:** 22. Juli 2026

**Phase:** B5.7 – Kontolebenszyklus, Sperren und Berechtigungen

## 1. Ergebnis

Für die acht untersuchten Legacy-Felder ist die fachliche Führung vollständig entschieden.

```text
untersuchte Felder:             8
beibehaltene Entscheidungen:    3
neue B5.7-Entscheidungen:       5
offene B5.7-Entscheidungen:     0
geprüfte Direktzugriffe:        153
```

PostgreSQL ist für alle acht Felder das führende System. `users.data` darf diese Zustände später nur noch als abgeleitete Legacy-Kompatibilitätsdarstellung enthalten.

## 2. Zentrale fachliche Trennung

- `Deleted` beschreibt eine logische Kontolöschung.
- `LockedOut` beschreibt eine administrative Kontosperre.
- `NeverDelete` schützt ausschließlich vor automatischer Inaktivitätsbereinigung.
- `Guest` ist eine Kontoklasse mit abweichendem Persistenz- und Passwortverhalten.
- `Hidden` betrifft nur die Sichtbarkeit in Benutzer- und Last-Caller-Listen.
- `sExpiryDate` und `ExpirySec` bilden gemeinsam eine zeitgesteuerte Autorisierungsänderung.

Insbesondere darf die Legacy-Ablaufregel nicht als Kontolöschung oder allgemeine Kontosperre umgesetzt werden.

## 3. Entscheidungsübersicht

| Feld | Kategorie | Status | PostgreSQL-Ziel | Lesen | Schreiben | Dateien |
|---|---|---|---|---:|---:|---:|
| `Security` | authorization | retained | `bbs_user_roles / bbs_role_capabilities` | 91 | 6 | 18 |
| `Deleted` | account-state | retained | `bbs_users.account_state / deleted_at` | 14 | 2 | 9 |
| `LockedOut` | account-state | retained | `bbs_users.account_state / locked_reason` | 8 | 1 | 5 |
| `NeverDelete` | retention-policy | decided | `bbs_users.auto_delete_exempt (planned)` | 3 | 1 | 2 |
| `Guest` | account-kind | decided | `bbs_users.account_kind (planned)` | 5 | 1 | 4 |
| `Hidden` | profile-visibility | decided | `bbs_user_profiles.is_hidden (planned)` | 6 | 1 | 4 |
| `sExpiryDate` | authorization-expiry | decided | `bbs_user_authorization_expiry.effective_at (planned)` | 4 | 4 | 5 |
| `ExpirySec` | authorization-expiry | decided | `bbs_user_authorization_expiry.post_expiry_policy (planned)` | 3 | 3 | 4 |

## 4. Einzelentscheidungen

### `Security`

**Legacy-Semantik:** Numerischer Sicherheitslevel mit Flags und Gegenflags

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_roles / bbs_role_capabilities`

**Migrationsregel:** Legacy-Level niemals numerisch kopieren; in geprüfte Rollen und Capabilities übersetzen

**Schreibregel:** Änderung ausschließlich über die administrative Autorisierungsfunktion

**Audit:** Jede Rollen- oder Capability-Änderung mit Akteur, Betroffenem und authz_revision protokollieren

### `Deleted`

**Legacy-Semantik:** Logische Löschmarkierung des Benutzerkontos

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_users.account_state / deleted_at`

**Migrationsregel:** Legacy-Bit aus dem konsistenten PostgreSQL-Löschzustand ableiten

**Schreibregel:** Nur ausdrückliche, auditierte logische Löschung oder Wiederherstellung

**Audit:** Löschung und Wiederherstellung mit Akteur, Grund und Zeitstempel protokollieren

### `LockedOut`

**Legacy-Semantik:** Administrative Kontosperre

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_users.account_state / locked_reason`

**Migrationsregel:** Nicht mit temporärem Login-Throttling vermischen

**Schreibregel:** Nur ausdrückliche administrative Sperrung oder Entsperrung

**Audit:** Sperrung und Entsperrung mit Akteur, Grund und Zeitstempel protokollieren

### `NeverDelete`

**Legacy-Semantik:** Ausnahme von der automatischen Inaktivitätslöschung

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_users.auto_delete_exempt (planned)`

**Migrationsregel:** Booleschen Legacy-Wert übernehmen; schützt nicht vor ausdrücklicher Admin-Löschung

**Schreibregel:** Nur administrativ änderbar; automatische Bereinigung muss den Wert beachten

**Audit:** Jede Änderung der Löschschutz-Ausnahme mit Akteur und Grund protokollieren

### `Guest`

**Legacy-Semantik:** Gastkonto ohne normalen Passwortwechsel, Logout-Writeback oder automatische Löschung

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_users.account_kind (planned)`

**Migrationsregel:** Als Kontoklasse standard oder guest modellieren; nicht allein als Rolle abbilden

**Schreibregel:** Nur administrativ änderbar; Gastverhalten zentral aus der Kontoklasse ableiten

**Audit:** Jede Änderung der Kontoklasse mit Akteur und Grund protokollieren

### `Hidden`

**Legacy-Semantik:** Unterdrückt Benutzer in Benutzerlisten und Last-Caller-Anzeigen

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_profiles.is_hidden (planned)`

**Migrationsregel:** Booleschen Sichtbarkeitswert ohne Einfluss auf Login oder Kontostatus übernehmen

**Schreibregel:** Zunächst nur administrativ änderbar; spätere Selbstverwaltung separat entscheiden

**Audit:** Jede administrative Sichtbarkeitsänderung protokollieren

### `sExpiryDate`

**Legacy-Semantik:** Datum einer zeitgesteuerten Herabstufung der Legacy-Berechtigung

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_authorization_expiry.effective_at (planned)`

**Migrationsregel:** DD-MM-YYYY geprüft konvertieren; 00-00-0000 wird NULL; Wirksamkeit ab lokalem Tagesbeginn

**Schreibregel:** Nur administrativ als geplante Autorisierungsänderung setzen oder entfernen

**Audit:** Planung, Änderung, Ausführung und Aufhebung der Ablaufregel protokollieren

### `ExpirySec`

**Legacy-Semantik:** Vollständiger Legacy-Sicherheitszustand nach Eintritt des Ablaufdatums

**Führung:** PostgreSQL

**PostgreSQL-Ziel:** `bbs_user_authorization_expiry.post_expiry_policy (planned)`

**Migrationsregel:** Level, Flags und Gegenflags in eine geprüfte Rollen- und Capability-Policy übersetzen; niemals numerisch kopieren

**Schreibregel:** Nur zusammen mit der Ablaufregel administrativ ändern

**Audit:** Zielpolicy und ausgeführte Rollen- oder Capability-Änderungen protokollieren

## 5. Konsequenzen für die Umsetzung

1. Numerische Legacy-Sicherheitswerte werden nicht direkt nach PostgreSQL kopiert.
2. Rollen und Capabilities bleiben die einzige moderne Autorisierungsquelle.
3. Kontolöschung, administrative Sperre und temporäres Login-Throttling bleiben getrennte Zustände.
4. Die Ablaufregel wird als geplante Änderung einer Autorisierungs-Policy modelliert.
5. `mbsetup` darf diese PostgreSQL-geführten Zustände nicht durch vollständige Legacy-Datensatz-Rewrites zurücksetzen.

Die konkreten PostgreSQL-Migrationen und administrativen Schreibschnittstellen folgen in einer späteren Umsetzungsphase.
