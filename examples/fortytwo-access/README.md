# FortyTwo BBS access examples

These files document the tested Telnet and SSH access setup for FortyTwo BBS.

## Files

- `fortytwo-telnet.xinetd.in`
  - xinetd service on `127.0.0.1:2323`
  - starts `telnetd` with `-h -E`
  - suppresses host and kernel information
  - runs the FortyTwo `mblogin` program

- `issue.in`
  - login banner displayed before the Telnet login prompt
  - explains login, registration and SSH availability

- `fortytwo-bbs-ssh.in`
  - forced-command wrapper for registered SSH users
  - rejects client-supplied commands
  - requires a terminal
  - starts only FortyTwo BBS with a clean environment

- `sshd_config_fortytwo.in`
  - separate OpenSSH instance on `127.0.0.1:2222`
  - allows only members of `fortytwo-bbs-users`
  - disables SFTP, SCP commands, forwarding, tunnelling and user startup files
  - forces the FortyTwo SSH wrapper

## Placeholders

Replace these placeholders during installation:

- `@FORTYTWO_ROOT@`
  - FortyTwo BBS installation directory
  - example: `/opt/fortytwo`

- `@FORTYTWO_SSH_WRAPPER@`
  - absolute path to the installed SSH wrapper
  - example: `/usr/local/libexec/fortytwo-bbs-ssh`

## Access policy

Telnet is currently tested for existing-user login. The login flow can hand
unknown users to `mbnewusr` when `ASK_NEWUSER` is enabled, but registration
must remain disabled until account creation is isolated and hardened.

SSH is intended for registered users only.

The examples bind exclusively to localhost for testing. Do not expose the
services externally until authentication, registration, rate limiting,
permissions and logging have been reviewed for the target system.
