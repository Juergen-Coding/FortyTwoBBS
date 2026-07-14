# fortytwo-authd – Phase B1

Stand: 0.1.0

Diese Phase ergänzt das vorhandene FTAP-1.1-Paket um das erste ausführbare
Grundgerüst von `fortytwo-authd`.

## Enthalten

- validierte Kommandozeilenkonfiguration,
- sicherer Unix-Domain-Socket-Listener,
- Prüfung lokaler Peer-Credentials mit `SO_PEERCRED`,
- explizite UID-Freigabeliste,
- nichtblockierende Verarbeitung mehrerer Verbindungen über `poll()`,
- korrekte Verarbeitung partieller Reads und Writes,
- HELLO-Frist pro neuem Client,
- echte FTAP-Kommunikation `HELLO` → `HELLO_OK`,
- FTAP-Fehlerantworten für valide, aber unzulässige Frames,
- stilles Schließen bei nicht vertrauenswürdigem Magic oder Request-ID,
- kontrollierter Shutdown über `SIGINT` und `SIGTERM`,
- Schutz vor dem Löschen ersetzter Socket-Dateien über Geräte-/Inode-Prüfung,
- Unit- und Integrationstests einschließlich ASan und UBSan.

## Bewusste Grenze dieser Phase

Phase B1 führt noch keine Passwortprüfung, Datenbankverbindung,
Sitzungserzeugung oder Service-Bindung aus.

Nach einem erfolgreichen `HELLO` bleibt die Verbindung bestehen. Weitere,
bereits formal gültige FTAP-Anfragen erhalten bis zur jeweiligen
Implementierungsphase `FTAP_ERR_INTERNAL` und die Verbindung wird geschlossen.

## Bauen und testen

```bash
make -C fortytwo-auth test
make -C fortytwo-auth sanitize-test
```

Das ausführbare Programm entsteht unter:

```text
fortytwo-auth/build/normal/fortytwo-authd
```

## Konfiguration prüfen

```bash
fortytwo-auth/build/normal/fortytwo-authd \
  --socket /tmp/fortytwo-auth.sock \
  --allow-uid "$(id -u)" \
  --check-config
```

## Lokaler Teststart

```bash
fortytwo-auth/build/normal/fortytwo-authd \
  --socket /tmp/fortytwo-auth.sock \
  --socket-mode 0600 \
  --allow-uid "$(id -u)" \
  --verbose
```

Das Grundgerüst ist noch nicht als dauerhafter Systemdienst vorgesehen. Die
technischen Dienstkonten, Laufzeitverzeichnisse und die endgültige
Systemd-/Podman-Einbindung folgen in einer späteren Phase.
