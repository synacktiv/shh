# Supported systemd options

- [`CapabilityBoundingSet`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#CapabilityBoundingSet=)

  - *dynamic blacklisting*

- [`IPAddressDeny`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#IPAddressDeny=)

  - `any`
  - to support this option, other options may be dynamically enabled:
    - [`IPAddressAllow`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#IPAddressAllow=)

- [`InaccessiblePaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#InaccessiblePaths=)

  - *dynamic path blacklisting*
  - to support this option, other options may be dynamically enabled:
    - [`TemporaryFileSystem`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#TemporaryFileSystem=)
    - [`BindReadOnlyPaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#BindReadOnlyPaths=)
    - [`BindPaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#BindPaths=)

- [`LockPersonality`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#LockPersonality=)

  - `true`

- [`MemoryDenyWriteExecute`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#MemoryDenyWriteExecute=)

  - `true`

- [`NoExecPaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#NoExecPaths=)

  - *dynamic path blacklisting*
  - to support this option, other options may be dynamically enabled:
    - [`ExecPaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ExecPaths=)

- [`PrivateDevices`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#PrivateDevices=)

  - `true`

- [`PrivateNetwork`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#PrivateNetwork=)

  - `true`

- [`PrivateTmp`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#PrivateTmp=)

  - `disconnected`

- [`ProtectClock`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectClock=)

  - `true`

- [`ProtectControlGroups`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectControlGroups=)

  - `true`

- [`ProtectHome`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectHome=)

  - `tmpfs`
  - `read-only`
  - `true`

- [`ProtectKernelLogs`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectKernelLogs=)

  - `true`

- [`ProtectKernelModules`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectKernelModules=)

  - `true`

- [`ProtectKernelTunables`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectKernelTunables=)

  - `true`

- [`ProtectProc`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectProc=)

  - `ptraceable`

- [`ProtectSystem`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ProtectSystem=)

  - `true`
  - `full`
  - `strict`

- [`ReadOnlyPaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ReadOnlyPaths=)

  - *dynamic path blacklisting*
  - to support this option, other options may be dynamically enabled:
    - [`ReadWritePaths`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#ReadWritePaths=)

- [`RestrictAddressFamilies`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#RestrictAddressFamilies=)

  - *dynamic whitelisting*

- [`RestrictRealtime`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#RestrictRealtime=)

  - `true`

- [`SocketBindDeny`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#SocketBindDeny=)

  - *dynamic blacklisting*

- [`SystemCallArchitectures`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#SystemCallArchitectures=)

  - `native`

- [`SystemCallFilter`](https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html#SystemCallFilter=)

  - *dynamic blacklisting*
