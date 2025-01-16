# Changelog

## v2025.1.16

### <!-- 01 -->💡 Features

- Update options for systemd v257 ([2ca1c42](https://github.com/desbma/shh/commit/2ca1c42bc64e15ac0a6a249879a6427142c3be7b) by desbma)
- Add shh version in unit fragment header ([81bf6fd](https://github.com/desbma/shh/commit/81bf6fdbbde46556c18b3d329ad629db8f3d5487) by desbma)

### <!-- 02 -->🐛 Bug fixes

- strace-parser: Indexed arrays ([f3c0c2f](https://github.com/desbma/shh/commit/f3c0c2ff529fb051051246447063a36700b5885a) by desbma)

### <!-- 04 -->📗 Documentation

- Add changelog ([01ca7a1](https://github.com/desbma/shh/commit/01ca7a1c246ef9b87c68a5e161744b2dc04046d6) by desbma)
- Add man pages ([53ba284](https://github.com/desbma/shh/commit/53ba28462f53a3d4a785679594b6662bc8185148) by desbma)
- README: Add portability warning ([a9439ae](https://github.com/desbma/shh/commit/a9439ae72af4039987de64e9a1e168598f9df766) by desbma)
- Update changelog template ([e666607](https://github.com/desbma/shh/commit/e6666075082198b23ec15e26468d45a0e196b73c) by desbma)

### <!-- 05 -->🧪 Testing

- Add mknod integration test ([c6284af](https://github.com/desbma/shh/commit/c6284af106ddfbe891b424ee5ef587ee300a7a30) by desbma-s1n)
- Simplify reference string definitions ([6971f54](https://github.com/desbma/shh/commit/6971f54b281022258a8ea076fa075b1240d304cb) by desbma)
- Fix integration tests for PrivateTmp=disconnected broken by 2ca1c42 ([7a32f7e](https://github.com/desbma/shh/commit/7a32f7e53ff6270dfcc069292def1feaa0933fb0) by desbma)

### <!-- 06 -->🚜 Refactor

- Drop peg strace parser ([5f1a98c](https://github.com/desbma/shh/commit/5f1a98cd46195a0781a2c81b0c2b6e79deccd787) by desbma)
- summary: Split summary into per syscall group functions ([83fc818](https://github.com/desbma/shh/commit/83fc81824ee9565b9f222e3701e3769dc12ce28c) by desbma)
- Factorize unit fragment header creation ([0687e63](https://github.com/desbma/shh/commit/0687e6313ce98bc865b8624e42fa11b99243bb34) by desbma)

### <!-- 08 -->🏗  Build

- Release script auto version ([6fbca7e](https://github.com/desbma/shh/commit/6fbca7e9e590064235218b9b97a47c9d43b59a78) by desbma)
- Remove unmaintained prettier pre-commit hook ([9c8a960](https://github.com/desbma/shh/commit/9c8a96027392115a53b0afa45e15403d3acab196) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Update lints for rust 1.83 ([ca2d791](https://github.com/desbma/shh/commit/ca2d79142073c0247c9b2d9d9ff3d7074ad761bf) by desbma)
- Add pre-commit hooks ([15df8ba](https://github.com/desbma/shh/commit/15df8ba7564b1ad879e3f33487c59827a786fd84) by desbma)

---

## v2024.11.23

### <!-- 01 -->💡 Features

- Support for CapabilityBoundingSet systemd option (WIP) ([8f6a472](https://github.com/desbma/shh/commit/8f6a4725ac322a85b38e417f45c4b6bb2f216b34) by desbma)
- Cl goodies ([57fbeb5](https://github.com/desbma/shh/commit/57fbeb52b4ddc0f41a3b6bd44357135c68367e10) by desbma)
- Support CAP_BLOCK_SUSPEND capability ([8e0530c](https://github.com/desbma/shh/commit/8e0530c558aaed20479c9c2591794446e467831f) by desbma)
- Support CAP_BPF capability ([62bb876](https://github.com/desbma/shh/commit/62bb8762a20688ad0c11d8a6c601363c0422c739) by desbma)
- Support CAP_SYS_CHROOT capability ([ca7ab16](https://github.com/desbma/shh/commit/ca7ab16bbb297d38b16805fe5153e60a6cc57079) by desbma)
- Support CAP_NET_RAW capability ([47f333a](https://github.com/desbma/shh/commit/47f333a9bd4eb9fd724773eb66d827d8cfdd49bd) by desbma)
- Support CAP_SYS_TIME capability ([8f47d34](https://github.com/desbma/shh/commit/8f47d347369fc0fe260c167439921c4b46d97c5c) by desbma)
- Support CAP_PERFMON capability ([e717bdd](https://github.com/desbma/shh/commit/e717bdd137e88efb0e3d48926dd5805829e261aa) by desbma)
- Support CAP_SYS_PTRACE capability ([f46a220](https://github.com/desbma/shh/commit/f46a2206e6811830b64d350ceda130dd1d522cd8) by desbma)
- Support CAP_SYSLOG capability ([9c5f65f](https://github.com/desbma/shh/commit/9c5f65f979d975c300db7c14033d66b93281c59d) by desbma)
- Support CAP_MKNOD capability ([169536e](https://github.com/desbma/shh/commit/169536e42977115afa3f931b1a387fc25069a510) by desbma)
- Support CAP_SYS_TTY_CONFIG capability ([b348788](https://github.com/desbma/shh/commit/b3487883532c2f15d4c5c77ab702360ad436c327) by desbma)
- Support CAP_WAKE_ALARM capability ([94082a0](https://github.com/desbma/shh/commit/94082a0c2bb0f009db0ef1e545a3bbf1d6baac4a) by desbma)
- Support negative sets ([baeea83](https://github.com/desbma/shh/commit/baeea830eae03062be7f664fa6cd42ca25ce37fe) by desbma)
- Changeable effects ([fc69691](https://github.com/desbma/shh/commit/fc6969181148176a3f3876ee66e251ed3d135975) by desbma-s1n)
- Add network firewalling option ([4722239](https://github.com/desbma/shh/commit/4722239c8fb3c68b8a05dcb3006d47e12321dd7a) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Force StandardOutput=journal when profiling ([852b37c](https://github.com/desbma/shh/commit/852b37cd8ecb70ed792d321b695b9b2c656fae59) by desbma)
- Comment typo ([04b1887](https://github.com/desbma/shh/commit/04b1887084c543df07af8c348bb90e129aaa8341) by desbma)
- Comment typo ([63770db](https://github.com/desbma/shh/commit/63770dbb3817f54cd8e43d75f4a22c9e42f3cd2d) by desbma-s1n)

### <!-- 04 -->📗 Documentation

- README: Minor clarification ([fb5c6af](https://github.com/desbma/shh/commit/fb5c6af1d145d7bc4f48629567ce6cd6f9133f29) by desbma)
- Add comments ([d91cd42](https://github.com/desbma/shh/commit/d91cd4207551ac4a96e8804da966708b4922ab89) by desbma)
- Add option model comment ([4cc41a9](https://github.com/desbma/shh/commit/4cc41a98fec31244d49abe1968a525be6bd42fe8) by desbma)
- Update capabilities TODOs ([0dc33c0](https://github.com/desbma/shh/commit/0dc33c05c4ee1e7cc98792c6bb62a11572125b63) by desbma)
- Add autogenerated list of supported systemd options ([9ea16cb](https://github.com/desbma/shh/commit/9ea16cba73908a4ead02d7d07f4f55aed7423a92) by desbma)

### <!-- 05 -->🧪 Testing

- Add CapabilityBoundingSet integration tests ([a98859a](https://github.com/desbma/shh/commit/a98859a2e0be45725627206697ef10d1a50992b5) by desbma-s1n)

### <!-- 06 -->🚜 Refactor

- peg: Match on rules instead of tags ([cb97a99](https://github.com/desbma/shh/commit/cb97a998e1d70f53c48f89050c8ce2f458f0b839) by desbma-s1n)
- Effect/option types ([26c7f41](https://github.com/desbma/shh/commit/26c7f41977010492f85e74efd623b40a526f53ae) by desbma)
- String -> & 'static str ([af995f0](https://github.com/desbma/shh/commit/af995f05218a44b0ee5abe62964d54ffa4abb2e9) by desbma)
- Replace lazy_static by LazyLock ([192c8ad](https://github.com/desbma/shh/commit/192c8ad8f7d49a1fa75b8c777dd2ca564140be16) by desbma)
- Use Option::transpose ([bc55cb1](https://github.com/desbma/shh/commit/bc55cb1581679628e1fb737a625e12cbca63a917) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Update release script ([c1b79db](https://github.com/desbma/shh/commit/c1b79db77758dec8a321b6dd62626766be9d89c1) by desbma)
- Enable more lints ([7620b50](https://github.com/desbma/shh/commit/7620b50e13dbc1d864a3f7ce515d030c49310354) by desbma)
- Update dependencies ([5c4454b](https://github.com/desbma/shh/commit/5c4454bc96eed23e307b774e992b788e143c5243) by desbma)

---

## v2024.6.4

### <!-- 01 -->💡 Features

- Add error context if starting strace fails ([eb0bca2](https://github.com/desbma/shh/commit/eb0bca27f774a72a17e313a4b4f25e546ac363c2) by desbma-s1n)
- Add PEG based Pest parser ([d0c570f](https://github.com/desbma/shh/commit/d0c570fecdc5bdb9456ea9a30d7b500c98c91a8b) by desbma-s1n)
- Add optional strace log mirror output ([76f3c14](https://github.com/desbma/shh/commit/76f3c1474645e2e7522c26ede670012a94ec2136) by desbma-s1n)
- Combinator based parser ([40086ae](https://github.com/desbma/shh/commit/40086ae63824351d7b67cedc191b3c9c3724fab0) by desbma-s1n)

### <!-- 02 -->🐛 Bug fixes

- Handling of '+' prefixed ExecStart directives ([776b146](https://github.com/desbma/shh/commit/776b14624a27fd20f64bd879491f8344c6872887) by desbma)
- Clippy false positive ([0ec360b](https://github.com/desbma/shh/commit/0ec360b36227bcd0570c372cc75b350eed7c3583) by desbma)

### <!-- 03 -->🏃 Performance

- Add parse_line bench ([c57daee](https://github.com/desbma/shh/commit/c57daeead9e5d31f2ea7f97063102988f39073ae) by desbma-s1n)

### <!-- 06 -->🚜 Refactor

- Improve incomplete syscall types + move handling out of parser ([ae3ea4f](https://github.com/desbma/shh/commit/ae3ea4fcfee7eca8a67d4e6a307553e01a0f5223) by desbma-s1n)
- Remove legacy regex parser ([d43a9a0](https://github.com/desbma/shh/commit/d43a9a0a2c3eaccaa69cb356eebe7a0902ece4d4) by desbma-s1n)

### <!-- 10 -->🧰 Miscellaneous tasks

- Merge imports ([bd6b6b5](https://github.com/desbma/shh/commit/bd6b6b57ff270c2ec1b6dc5d86d770d8a353b427) by desbma-s1n)

---

## v2024.4.5

### <!-- 01 -->💡 Features

- Build deb with glibc ([09e6f66](https://github.com/desbma/shh/commit/09e6f66d8d35139350b0b442b1e3696a41560381) by desbma-s1n)

### <!-- 02 -->🐛 Bug fixes

- Strace array parsing (fixes #3) ([be5dd32](https://github.com/desbma/shh/commit/be5dd32d188094822bca2394da0c2d53805d86b8) by desbma)
- Parsing of multiline ExecStartXxx commands ([91d363c](https://github.com/desbma/shh/commit/91d363c1a5d66241daa4297ae46c88cdb138483a) by desbma-s1n)
- Handling of required command line multiple arguments ([79ec626](https://github.com/desbma/shh/commit/79ec6267239e3b29d0576ca62f954c1cabfb60c6) by desbma-s1n)

### <!-- 04 -->📗 Documentation

- Swap official/mirror repository roles ([a782302](https://github.com/desbma/shh/commit/a782302d18a55e2e549d0ef257ef1c84ebcec956) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- More clippy lints ([734c090](https://github.com/desbma/shh/commit/734c0901f9156a1d995a6d4b60370e2aeeba6ece) by desbma)
- Modeling -> model ([b0526b5](https://github.com/desbma/shh/commit/b0526b500757496a3829c262c19eb61666396f59) by desbma-s1n)

---

## v2023.12.16

### <!-- 02 -->🐛 Bug fixes

- Stopping some services like nginx ([c80f428](https://github.com/desbma/shh/commit/c80f4280843dc5782b852dd620abb965b76a7aac) by desbma)
- Don't wait on systemctl if we don't need to ([b08881d](https://github.com/desbma/shh/commit/b08881d1e8572ebf867aa298d446a51798f92c78) by desbma)

---

## v2023.12.9

### <!-- 01 -->💡 Features

- Support services with multiple ExecStartPre/ExecStart/ExecStartPost directives ([30d15b5](https://github.com/desbma/shh/commit/30d15b5221f459f0d2a67041a926d521407e3841) by desbma)

---

## v2023.12.1

### <!-- 01 -->💡 Features

- README: Add blogpost backlink ([bcb50af](https://github.com/desbma/shh/commit/bcb50afb3ece1ec6ec37c9fd05df8fee1d54ef7c) by desbma-s1n)
- Parse strace version ([d4064c6](https://github.com/desbma/shh/commit/d4064c632152726a3ab02b7e057e10452b89a8e0) by desbma-s1n)

### <!-- 02 -->🐛 Bug fixes

- Systemd rc version parsing ([5c8ec20](https://github.com/desbma/shh/commit/5c8ec204dcc726bb36b296e4d81b72d30857fd76) by desbma-s1n)

### <!-- 04 -->📗 Documentation

- README: Add repo links ([d1d7102](https://github.com/desbma/shh/commit/d1d7102aff930d6d92765efcae4ae24a78514920) by desbma)
- README: Add AUR link ([2881aa2](https://github.com/desbma/shh/commit/2881aa2859d40d84f97972335b8f1eb8b3d99613) by desbma)
- README: Add badges ([e549755](https://github.com/desbma/shh/commit/e549755f2317e7e937c5ca3ee247756422cf8548) by desbma)

---

## v2023.10.26

### <!-- 02 -->🐛 Bug fixes

- List of address families missing some chars ([75eba5f](https://github.com/desbma/shh/commit/75eba5f2d34ff165b968cf98d1bfd2f1075c0ffa) by desbma-s1n)

---

## v2023.10.19

### <!-- 02 -->🐛 Bug fixes

- Work around inconsistent strace 5.10 output ([86e9d54](https://github.com/desbma/shh/commit/86e9d54953174d38ea63a9270d7248e93b944f74) by desbma-s1n)

---

## v2023.10.2

### <!-- 01 -->💡 Features

- Support LockPersonality systemd option ([d46c422](https://github.com/desbma/shh/commit/d46c4221b4a42d575895d4b8c09879b00ec6e8f8) by desbma-s1n)
- Support RestrictRealtime systemd option ([93e9efb](https://github.com/desbma/shh/commit/93e9efbc28fce9a9167d62331e38be7b7d42d0a5) by desbma-s1n)
- Support ProtectClock systemd option ([f995ed2](https://github.com/desbma/shh/commit/f995ed28f67dd26bc8fc187f3d08aaeaa9f99267) by desbma-s1n)
- Support SocketBindDeny systemd option ([4927217](https://github.com/desbma/shh/commit/492721769b44854b3345b4932147c46946dd3551) by desbma-s1n)

### <!-- 02 -->🐛 Bug fixes

- Track socket protocols per process ([0b67312](https://github.com/desbma/shh/commit/0b6731261f8fedebbbc5beac2c18a61cb38bc546) by desbma-s1n)

### <!-- 05 -->🧪 Testing

- Script to run integration tests as {user,root} and from /{home,tmp} ([0dfe73f](https://github.com/desbma/shh/commit/0dfe73feb4fa5b2971516f9ec75c6aed883ab085) by desbma-s1n)
- Simplify dmesg test ([92cef27](https://github.com/desbma/shh/commit/92cef27df1ba6d6419e8fbe6fa127fa0339ead39) by desbma-s1n)

---

## v2023.9.27

### <!-- 01 -->💡 Features

- Detect unsupported services and throw error ([c3cab7b](https://github.com/desbma/shh/commit/c3cab7b65017abe9f9ddd998dd7cdc046d3bef5c) by desbma-s1n)
- Support RestrictAddressFamilies systemd option ([10d0dad](https://github.com/desbma/shh/commit/10d0dad0cc7327899391f0401fceaaf6dbe7b664) by desbma-s1n)
- Support MemoryDenyWriteExecute systemd option ([3d0daf1](https://github.com/desbma/shh/commit/3d0daf1efa6916abf7d822e380548541cda47f77) by desbma-s1n)
- Improve summary code to do a single hashmap search + support some more syscalls ([8dd0668](https://github.com/desbma/shh/commit/8dd06680ed0525fc12b89d12b3ca2147e78f53a0) by desbma-s1n)
- Add optional aggressive mode + support PrivateNetwork systemd option ([1cdb462](https://github.com/desbma/shh/commit/1cdb4627d07ab1c838e83f4b1351b1678b764351) by desbma-s1n)
- Support SystemCallArchitectures systemd option ([8f66c05](https://github.com/desbma/shh/commit/8f66c0586496849c5cb7a8ded04bf8541dc6c6e0) by desbma-s1n)
- Return EPERM instead of killing with signal when denied syscall is called ([5aefc36](https://github.com/desbma/shh/commit/5aefc36d85d9eb47c360f572fbb68fe8f36853d5) by desbma-s1n)

### <!-- 02 -->🐛 Bug fixes

- Recvmsg strace parsing ([b393dda](https://github.com/desbma/shh/commit/b393dda3d450bdd5e9bc481fda2317582c293fbd) by desbma-s1n)
- Handling of systemd syscall classes containing classes ([f98d508](https://github.com/desbma/shh/commit/f98d508e0cbd995b91f1ed3342b664c6dd5e3359) by desbma)

### <!-- 09 -->🤖 Continuous integration

- Initial GitHub actions config ([5695367](https://github.com/desbma/shh/commit/56953676d1464acb4799706c31f48c039ecabbe6) by desbma-s1n)
- GitHub actions release workflow ([12d0212](https://github.com/desbma/shh/commit/12d02127c8ad7d8a87cf385870d87c1d7a8b433a) by desbma-s1n)

### <!-- 10 -->🧰 Miscellaneous tasks

- Lint ([bc90525](https://github.com/desbma/shh/commit/bc90525d7c2c94bd9adef53de1a8695317f3647f) by desbma-s1n)
- Add release script ([7997c99](https://github.com/desbma/shh/commit/7997c991e6983bd59ccbd2c47af60e1216f481c0) by desbma-s1n)
