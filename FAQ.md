# FAQ

## How does `shh` work?

See [here](https://www.synacktiv.com/publications/systemd-hardening-made-easy-with-shh) for a high level introduction.

## How secure is the hardening produced byt SHH?

It relies on systemd to apply service unit options, and the Linux kernel to enforce them.
For a hardening setting to be circumvented or broken, a vulnerability would have to be exploited in either of those.

## Why use this instead of AppArmor/firejail/[other solution]?

The main advantage of using the systemd based hardening that SHH provides is its ubiquity.
Systemd is everywhere, and you don't have to install or enable anything, or configure complex LSM with new permission model to benefit from per-service hardening.
We believe this kind of hardening is vastly underused on most Linux systems, and that it is an easy way to raise the security level of a Linux system, which SHH makes accessible and convenient.

Also most other solutions rely on predefined per application profiles. If your application is not well known, you'd have to write a profile yourself, which can be time consuming and error prone. If you happen to be lucky and find a predefined profile, you also need to stay in the "expected" actions set that the program does. If you do, everything is good, however for anything unusual that the profile authors had not forseen, this will break at runtime. SHH relies solely on runtime profiling so this works even if your program is niche or not public, and by construction the hardening options will be generated to be tailored specifically for the program to be hardened.

## Can't the over-restrictive hardening break the service for legitimate use cases?

Breaking legitimate program flow because of too restrictive hardening is a common trap, which discourages many people and pushes them away from this approach.
SHH was designed from personal experience, to eliminate these risks, and save time by eliminating manual guesses of the right level of hardening:

- The hardening settings are generated only after runtime profiling.
- When building the set of hardening options, SHH sets each setting only if there is no doubt it can be enabled without breaking the program actions. In some cases, it can't be 100% sure, and for those the option is not enabled. This means that sometimes, an option that could have been enabled will me missed, but an option that has any risk of breaking something will never be set (barring a bug in SHH of course). In short, when in doubt, SHH favours _under_ hardening, over _over_ hardening.

## I know the service to be hardened very well, can I tell SHH to harden further?

By default, SHH apply a safe approach, however you can raise the security bar, with _a much more increased risk of breaking the service_, with theses options:

- `--mode aggressive`: Will set some options which can break the service in very niche cases, however it should be safe for most classic services.
- `--filesystem-whitelisting`: This option will basically build lists of paths accessed, and only allow access to those, by mounting read only or empty filesystems where it can. This is very powerful, but can only be done if the files accessed during profiling are representative of all future executions. For example for a file server, it will only allow access to files downloaded during profiling. You can also tweak the length of the path lists with the `--merge-paths-threshold` option.
- `--network-firewalling`: Like the previous option, this will only allow network traffic to peers/addresses/ports observed during profiling. You most likely don't want to use this unless for a local-only service: for example any use of DNS with changing IP will be denied if the IP was not seen during profiling.
