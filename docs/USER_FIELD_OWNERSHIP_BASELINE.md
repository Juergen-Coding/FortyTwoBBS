# FortyTwo BBS – B5.6 Hoheitsbaseline der Benutzerfelder

**Stand:** 22. Juli 2026
**Phase:** B5.6 – Feldhoheit und Migrationsreihenfolge

## 1. Zweck

Diese Baseline verbindet die B5.4-PostgreSQL-Zuordnung mit der in B5.5/B5.6 geprüften Schreiberinventur.

Sie übernimmt ausschließlich bereits dokumentierte Hoheitsentscheidungen. Offene Felder bleiben bis zu ihrer fachlichen Einzelprüfung Legacy-geführt.

## 2. Verbindlicher Ausgangsstand

```text
Felder insgesamt:                    72
bereits entschiedene Feldhoheiten:   10
offene Feldhoheiten:                 62
Felder mit direkten Schreibern:      58
Felder ohne direkte Schreiber:       14
von mbsetup direkt geschriebene:     40
von Ganzsatz-Rewrites betroffene:    72
```

## 3. Sicherheits- und Migrationsregel

Ein Feld ohne direkten Schreiber ist nicht automatisch schreibgeschützt oder entbehrlich. `mbsetup/m_users.c` liest und ersetzt vollständige `struct userrec`-Datensätze.

Dadurch können alle 72 Felder mit einem älteren Legacy-Stand zurückgeschrieben werden, auch wenn `mbsetup` das konkrete Feld weder anzeigt noch direkt bearbeitet.

Bis zur dokumentierten Einzelentscheidung bleibt für offene Felder `users.data` führend. Es findet kein automatischer PostgreSQL→Legacy- oder Legacy→PostgreSQL-Schreibabgleich statt.

## 4. Hoheitsmatrix

| Legacy-Feld | Bedeutung | Führung | PostgreSQL-Ziel | Status | direkte Writes | RMW | Writer-Komponenten | mbsetup-Writes | Ganzsatzrisiko |
|---|---|---|---|---|---:|---:|---|---:|---|
| `sUserName` | User First and Last Name | PostgreSQL | `bbs_user_profiles` / `display_name` | decided | 4 | 4 | `fortytwo-auth`, `lib`, `mbsebbs`, `mbsetup` | 2 | yes |
| `Name` | Unix name | PostgreSQL | `bbs_legacy_mbse_bindings` / `legacy_name` | decided | 4 | 0 | `fortytwo-auth`, `mbnntp`, `mbsebbs`, `mbsetup` | 1 | yes |
| `xPassword` | Keine Quellcodebeschreibung | PostgreSQL-Credential | keine Legacy-Übernahme | decided | 1 | 0 | `fortytwo-auth` | 0 | yes |
| `sVoicePhone` | Voice Number | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 4 | 0 | `mbsebbs`, `mbsetup` | 2 | yes |
| `sDataPhone` | Data/Business Number | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 5 | 0 | `mbsebbs`, `mbsetup` | 2 | yes |
| `sLocation` | Users Location | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 4 | 1 | `mbsebbs`, `mbsetup` | 2 | yes |
| `address` | Users address | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `mbsebbs`, `mbsetup` | 1 | yes |
| `sDateOfBirth` | Date of Birth | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 5 | 0 | `mbsebbs`, `mbsetup` | 2 | yes |
| `tFirstLoginDate` | Date of First Login | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 2 | 0 | `fortytwo-auth`, `mbsebbs` | 0 | yes |
| `tLastLoginDate` | Date of Last Login | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 4 | 0 | `fortytwo-auth`, `mbnntp`, `mbsebbs` | 0 | yes |
| `Security` | User Security Level | PostgreSQL | `bbs_user_roles / bbs_role_capabilities` / `Rollen- und Capability-Zuordnung` | decided | 6 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `sComment` | User Comment | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsetup` | 2 | yes |
| `sExpiryDate` | User Expiry Date | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 4 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 2 | yes |
| `ExpirySec` | Expiry Security Level | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `sSex` | Users Sex | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 7 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 3 | yes |
| `Hidden` | Hide User from Lists | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsetup` | 1 | yes |
| `HotKeys` | Hot-Keys ON/OFF | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 7 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `GraphMode` | ANSI ON/OFF | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 7 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `Deleted` | Deleted Status | PostgreSQL | `bbs_users` / `account_state / deleted_at` | decided | 2 | 0 | `mbsetup`, `mbutils` | 1 | yes |
| `NeverDelete` | Never Delete User | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsetup` | 1 | yes |
| `xChat` | Keine Quellcodebeschreibung | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `LockedOut` | User is locked out | PostgreSQL | `bbs_users` / `account_state / locked_reason` | decided | 1 | 0 | `mbsetup` | 1 | yes |
| `DoNotDisturb` | DoNot disturb | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 4 | 0 | `mbsebbs`, `mbsetup` | 1 | yes |
| `Cls` | CLS on/off | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `More` | More prompt | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `xFsMsged` | Keine Quellcodebeschreibung | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `MailScan` | New Mail scan | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 8 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `Guest` | Is guest account | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsetup` | 1 | yes |
| `OL_ExtInfo` | OLR extended msg info | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `mbsebbs`, `mbsetup` | 1 | yes |
| `iTotalCalls` | Total number of calls | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 2 | `mbnntp`, `mbsebbs` | 0 | yes |
| `iTimeLeft` | Time left today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 7 | 1 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 2 | yes |
| `iConnectTime` | Connect time this call | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 2 | 1 | `mbsebbs` | 0 | yes |
| `iTimeUsed` | Time used today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 1 | `mbsebbs`, `mbsetup` | 1 | yes |
| `xScreenLen` | Keine Quellcodebeschreibung | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `tLastPwdChange` | Date last password chg | PostgreSQL | `bbs_password_credentials` / `changed_at` | decided | 3 | 0 | `fortytwo-auth`, `mbsebbs` | 0 | yes |
| `xHangUps` | Keine Quellcodebeschreibung | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `Credit` | Users credit | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsetup` | 1 | yes |
| `Paged` | Times paged today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `MsgEditor` | Message Editor to use | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 9 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup`, `mbutils` | 1 | yes |
| `LastPktNum` | Todays Last packet number | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `Archiver` | Archiver to use | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 6 | 0 | `mbsebbs`, `mbsetup` | 2 | yes |
| `iLastFileArea` | Number of last file area | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs` | 0 | yes |
| `iLastFileGroup` | Number of last file group | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `sProtocol` | Users default protocol | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 5 | 1 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 2 | yes |
| `Downloads` | Total number of d/l's | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 2 | `mbsebbs` | 0 | yes |
| `Uploads` | Total number of uploads | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 2 | `mbsebbs` | 0 | yes |
| `UploadK` | Upload KiloBytes | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 1 | `mbsebbs` | 0 | yes |
| `DownloadK` | Download KiloBytes | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 1 | `mbsebbs` | 0 | yes |
| `DownloadKToday` | KB Downloaded today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 2 | `mbsebbs` | 0 | yes |
| `UploadKToday` | KB Uploaded today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 1 | `mbsebbs` | 0 | yes |
| `iTransferTime` | Last file transfer time | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `iLastMsgArea` | Number of last msg area | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs` | 0 | yes |
| `iLastMsgGroup` | Number of last msg group | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `iPosted` | Number of msgs posted | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 5 | `mbnntp`, `mbsebbs` | 0 | yes |
| `iLanguage` | Current Language | PostgreSQL | `bbs_user_profiles` / `language_code` | decided | 4 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `sHandle` | Users Handle | PostgreSQL | `bbs_user_profiles` / `handle` | decided | 7 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 2 | yes |
| `iStatus` | WhosDoingWhat status | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsebbs` | 0 | yes |
| `DownloadsToday` | Downloads today | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 1 | 0 | `mbsebbs` | 0 | yes |
| `CrtDef` | IEMSI Terminal emulation | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `Protocol` | IEMSI protocol | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `IEMSI` | Is this a IEMSI session | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `ieMNU` | Can do ASCII download | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `ieTAB` | Can handle TAB character | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 0 | 0 | keine direkten Schreiber | 0 | yes |
| `ieASCII8` | Can handle 8-bit IBM-PC | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 2 | 0 | `fortytwo-auth`, `mbsebbs` | 0 | yes |
| `ieNEWS` | Show bulletins | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 5 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `ieFILE` | Check for new files | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 8 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `Email` | Has private email box | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `FSemacs` | FSedit uses emacs keys | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `mbsebbs`, `mbsetup` | 1 | yes |
| `Password` | Plain password | PostgreSQL-Credential | keine Legacy-Übernahme | decided | 6 | 0 | `mbnntp`, `mbsebbs`, `mbsetup` | 1 | yes |
| `Charset` | Character set | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 0 | `fortytwo-auth`, `mbsebbs`, `mbsetup` | 1 | yes |
| `OLRext` | OLR extension counter | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 3 | 1 | `mbsebbs`, `mbsetup` | 1 | yes |
| `OLRlast` | OLR last download date | Legacy bis zur Einzelentscheidung | noch nicht festgelegt | open | 2 | 0 | `mbsebbs`, `mbsetup` | 1 | yes |

## 5. Nächste Entscheidungsblöcke

Die offenen Felder werden nicht alphabetisch, sondern nach fachlicher und technischer Kopplung entschieden:

1. Identität, Berechtigungen, Sperren und Kontolebenszyklus.
2. Dauerhafte Profil- und Terminalpräferenzen.
3. Login-, Sitzungs- und Tageszustände.
4. Upload-, Download- und Nachrichtenstatistiken.
5. IEMSI-, reservierte und offenbar obsolete Felder.

Für jeden Block werden PostgreSQL-Ziel, Datentyp, Schreibberechtigung, Audit-Ereignis und Legacy-Kompatibilitätsrichtung separat festgelegt.
