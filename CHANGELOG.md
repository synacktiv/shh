# Changelog

## v2025.10.22

### <!-- 01 -->💡 Features

- Don't buffer strace log output ([506cace](https://github.com/desbma/shh/commit/506caceb7068747aed051dbcb1c8b930d5e7b8f8) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Kill(pid, 0) handling ([9885c1a](https://github.com/desbma/shh/commit/9885c1a1444eabb52e2358fc82cf8d1c91d95d82) by desbma)
- Curl integration test ([2f027f1](https://github.com/desbma/shh/commit/2f027f13fb2724a18083152b95a1de96d2f3d7f7) by desbma)
- Stop sequence for sshd ([b3b3248](https://github.com/desbma/shh/commit/b3b32481cbebc49ad374b5b5489c3409a3b02415) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Fix lint ([c6f5ac7](https://github.com/desbma/shh/commit/c6f5ac74acf2434684133592b03ce44036ec2e8a) by desbma)

---

## v2025.9.22

### <!-- 01 -->💡 Features

- Add EWOULDBLOCK to "maybe successful" errnos ([238b20b](https://github.com/desbma/shh/commit/238b20b6c09ce1f95e6a1304626d4eccb499d2d5) by desbma)
- Generic hardening mode (closes #15) ([455336f](https://github.com/desbma/shh/commit/455336f38e8529cbd53dadb4e0b70f22c4ab85e1) by desbma)
- Initial CAP_KILL support ([d2edd5b](https://github.com/desbma/shh/commit/d2edd5bda8e2757fe35212d43430555019bb7175) by desbma)
- CAP_IPC_LOCK support ([343edb7](https://github.com/desbma/shh/commit/343edb792d4a2116f67b2f26935873acadbb3376) by desbma)
- Refresh existing hardening fragment ([b991c28](https://github.com/desbma/shh/commit/b991c2801203bc2a8b138effffb45e1571c2d6e1) by desbma)
- Initialize current working directory ([d2cd3ce](https://github.com/desbma/shh/commit/d2cd3ce56d058f54bbd95d37d5fb82e40b704fa0) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Minor comment typo ([a6f5281](https://github.com/desbma/shh/commit/a6f5281486f7a417e0ba3b19c8d89c18801c1c8f) by desbma)
- Bit shift parsing error ([b004891](https://github.com/desbma/shh/commit/b0048915e303c05bf70a695f944efd1832821ceb) by desbma)
- Msrv ([2b6411c](https://github.com/desbma/shh/commit/2b6411cdbf5b6f97e38b0a9d99c2af0454816b88) by desbma)
- Path resolution for special files ([fe5f2e5](https://github.com/desbma/shh/commit/fe5f2e567493fb150d73fc6c24b3aff977e51792) by desbma)

### <!-- 03 -->🏃 Performance

- Avoid sorting syscall names if we don't show them ([4626c67](https://github.com/desbma/shh/commit/4626c674b6da527c7d9d8d94256cf4a7340c9d04) by desbma)

### <!-- 05 -->🧪 Testing

- Use snapshot testing for verbose unit tests ([f737f55](https://github.com/desbma/shh/commit/f737f55ea3ab5c9810ab5b1010b2ba3017463f30) by desbma)

### <!-- 06 -->🚜 Refactor

- Sort enum members ([76f756d](https://github.com/desbma/shh/commit/76f756d1142e524e52733fae572a04ed67abb484) by desbma)

### <!-- 09 -->🤖 Continuous integration

- Add cargo audit workflow ([3620abe](https://github.com/desbma/shh/commit/3620abea9d34c73fc5c02f86046821b53203e6d4) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Fix lint ([71e9c81](https://github.com/desbma/shh/commit/71e9c8159f59baf6b435fb444f7b228311541d23) by desbma)
- Cleanup unneeded derive ([eb81f33](https://github.com/desbma/shh/commit/eb81f339097a9a4efdf921fbf0c491bc3403c4a3) by desbma)

---

## v2025.7.13

### <!-- 01 -->💡 Features

- Try to use RUNTIME_DIRECTORY first for strace pipe location ([8f3ce35](https://github.com/desbma/shh/commit/8f3ce3543a45707a698156dd3a88aacf19f818ec) by desbma)
- Consider errored syscalls to catch cases like EINPROGRESS ([3e8e4ad](https://github.com/desbma/shh/commit/3e8e4ad8285027d08a6c63f342fb53705650795b) by desbma)
- Identify more successful sycalls returning -1 ([1d971d4](https://github.com/desbma/shh/commit/1d971d458443a60226f9582450669b003426192c) by desbma)

### <!-- 04 -->📗 Documentation

- README: Mention nixpkgs repo ([53f37ce](https://github.com/desbma/shh/commit/53f37ce3ac28e043ce9e483cec0109a6934b11ac) by kuflierl)

### <!-- 10 -->🧰 Miscellaneous tasks

- Ignore verbose clippy lints ([2e96cb3](https://github.com/desbma/shh/commit/2e96cb348bafc45cd85c5d37f9343bf63d857aaa) by desbma)
- Update .gitignore ([e741484](https://github.com/desbma/shh/commit/e741484510211ef912d9570a006abe9eae03bebb) by desbma)
- Update dependencies ([5a398fa](https://github.com/desbma/shh/commit/5a398fa390f30039c4b2ff1472337a4cf5f0c2e7) by desbma)
- Update clippy template ([ee68b02](https://github.com/desbma/shh/commit/ee68b025ad446bff6781159e906cf0bcee1b4c3f) by desbma)

---

## v2025.6.5

### <!-- 02 -->🐛 Bug fixes

- Support kernels without /proc/sys/kernel/unprivileged_userns_clone ([f103b06](https://github.com/desbma/shh/commit/f103b06c756dbb43aec615b590680cc99cbb0f00) by desbma)

### <!-- 08 -->🏗  Build

- Fix empty commit created by release script when using jujutsu ([4c3e73e](https://github.com/desbma/shh/commit/4c3e73e0d1230ef417f6790a65a78c69d1552678) by desbma)

---

## v2025.6.4

### <!-- 01 -->💡 Features

- Static strace path support at compile time ([da62cee](https://github.com/desbma/shh/commit/da62ceeb227de853be06610721744667c6fe994b) by kuflierl)
- Add support for shell auto-complete generation with clap_complete ([74914dc](https://github.com/desbma/shh/commit/74914dc8cfd74dbd7e051a090cc4c1f561b8cdde) by kuflierl)
- Initial experimental support for systemd user instances ([8114943](https://github.com/desbma/shh/commit/8114943d615e6e0238294af2d3f083dc835f1d0b) by desbma)
- Improve timeout logic when waiting for profiling result ([2b0e5ec](https://github.com/desbma/shh/commit/2b0e5ecdec3f0a763552f282e469a4e18dfa0006) by desbma)
- strace: Parse mac addresses ([8da117a](https://github.com/desbma/shh/commit/8da117afce96ad63529a2a6821af0b85d25a6812) by desbma)
- strace: Handle in/out struct members ([40354fa](https://github.com/desbma/shh/commit/40354fac5e53b010a64985ff42970346df822f2d) by desbma)
- strace: Array index substraction & comments ([b66f934](https://github.com/desbma/shh/commit/b66f934daf340e4f56e6f1f36237bd04c8decd83) by desbma)
- strace: Output macro expressions ([b7b2d8b](https://github.com/desbma/shh/commit/b7b2d8b8ea0197d2e137658fc5c863aba7978fb6) by desbma)
- Remove duplicate options ([eb1b51b](https://github.com/desbma/shh/commit/eb1b51b20affdca110acdcc2bd0ab91de9157067) by desbma)
- strace: More debugging macros ([cec9289](https://github.com/desbma/shh/commit/cec9289a4d6945db9f64d5b4cd1cf98cec2d8684) by desbma)
- Support jujutsu in release script ([00a5f8e](https://github.com/desbma/shh/commit/00a5f8e4805502b0e15f06602b5907ede919b82c) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Use journalctl cursors and a retry loop to fix unreliability/fuzzyness ([c91a967](https://github.com/desbma/shh/commit/c91a96755d6ba6750f74e46f3f54fb428fb5e650) by desbma)
- Improve journald cursor handling logic ([ce02c5c](https://github.com/desbma/shh/commit/ce02c5c4bd7d9542e8927f09a5ca2c3f0bb5ab5e) by desbma)
- Only set NotifyAccess=all in profiling fragment for notify services ([815d0cb](https://github.com/desbma/shh/commit/815d0cb32ec30f9c93b91252f6f00dcf16505736) by desbma)

### <!-- 03 -->🏃 Performance

- Box some large enum members ([57c91bb](https://github.com/desbma/shh/commit/57c91bbe7523ee8958d68d7ef7c3977f5480c3e8) by desbma)

### <!-- 05 -->🧪 Testing

- Update for user instance ([06dacaf](https://github.com/desbma/shh/commit/06dacaf668b19a8b7156241b905bc97ab9e36c0b) by desbma)

### <!-- 06 -->🚜 Refactor

- Man page generation command ([849b9a6](https://github.com/desbma/shh/commit/849b9a6646981c83a72a977b6398371e29d3b928) by desbma)
- strace: Macro as integer expression ([9bb8c28](https://github.com/desbma/shh/commit/9bb8c287597338ac74b84af6ab9e56f3bd2293a6) by desbma)
- NamedConst -> NamedSymbol ([4dcebed](https://github.com/desbma/shh/commit/4dcebed9e44b925c10bfda7a545794ac0c8780eb) by desbma)
- strace: Remove unused buffer format handling ([ad8866a](https://github.com/desbma/shh/commit/ad8866a8007fef98a34de15cbcc45613e98b17fb) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Fix rust 1.87 clipp::unnecessary_debug_formatting spam ([3ce85c4](https://github.com/desbma/shh/commit/3ce85c44c7228255539f9293591cd8d6b2659ea5) by desbma)

---

## v2025.4.12

### <!-- 01 -->💡 Features

- Model disabled mount propagation to host ([70637d4](https://github.com/desbma/shh/commit/70637d4d33b660c73e74cf7304ae69bbcdd916cf) by desbma)
- Support PrivateMounts systemd option ([ca293da](https://github.com/desbma/shh/commit/ca293dac64c6022d802439ad6bfeffb4490fca68) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Handle namespace pseudo files ([6f75bd9](https://github.com/desbma/shh/commit/6f75bd91c0569b4453a3f9880ca78b67fc483803) by desbma)

### <!-- 05 -->🧪 Testing

- Add netns systemd-run test ([7162280](https://github.com/desbma/shh/commit/7162280cf0a0d53cd3f4da6e6e863cb0a3212c1f) by desbma)
- options: Remove checks of options that vary too much between environments ([1f18b17](https://github.com/desbma/shh/commit/1f18b171cf45043fae01ff24aa4b6fb79dc577c9) by desbma)

### <!-- 08 -->🏗  Build

- Generate systemd syscall classes at build time from systemd-analyze output ([c52a860](https://github.com/desbma/shh/commit/c52a860e31bf476c845d1994f65431f3078bc344) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Update dependencies ([70d2142](https://github.com/desbma/shh/commit/70d21422b42f4848fe9a4b09bf6e32d43c220816) by desbma)
- Update lints, update to 2024 edition ([a625d11](https://github.com/desbma/shh/commit/a625d11d4edbc14eb81c07a9ab197375ae4e989f) by desbma)

---

## v2025.3.13

### <!-- 10 -->🧰 Miscellaneous tasks

- Lint ([5bf6fd2](https://github.com/desbma/shh/commit/5bf6fd20af840846bc8b29bba8e0c8721134f263) by desbma)

---

## v2025.3.12

### <!-- 01 -->💡 Features

- ProcSubset systemd option ([365f76d](https://github.com/desbma/shh/commit/365f76d02de48dce433b8ce88f9cc35ec57f7bc2) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Non leaf symlinks not being canonicalized ([6e90c41](https://github.com/desbma/shh/commit/6e90c418b4a484a31d00193bf4ae682df7642aa9) by desbma)

### <!-- 04 -->📗 Documentation

- README: Update shh run example output ([7ba62e3](https://github.com/desbma/shh/commit/7ba62e32e73fcc947853bf1d7e3cc7c19e950a32) by desbma)
- README: Split crates.io installation instructions + minor tweaks ([7312ae4](https://github.com/desbma/shh/commit/7312ae4dca2bf7c58354b02cc5a261c90385cf2e) by desbma)
- FAQ: Minor typo fix ([9176a6d](https://github.com/desbma/shh/commit/9176a6d095dd3e73ebdefbf16a7ff66598c84aa0) by desbma)

### <!-- 05 -->🧪 Testing

- Add ProcSubset integration test ([4ca7a12](https://github.com/desbma/shh/commit/4ca7a129251a632650f6241abe2382df3b8a26d4) by desbma)

### <!-- 06 -->🚜 Refactor

- Rename 'cl' integration tests to 'options' ([b7e6478](https://github.com/desbma/shh/commit/b7e64789ec90637f6268cbd1ae0d13848fdec980) by desbma)

---

## v2025.2.7

### <!-- 01 -->💡 Features

- Track IPv4 addresses ([b4dc2c1](https://github.com/desbma/shh/commit/b4dc2c19178fa649bccac386f732351532c05de3) by desbma)
- IpAddressDeny (WIP) ([8df9a0c](https://github.com/desbma/shh/commit/8df9a0c55c0ee45e0fd7efe9f2c598ebec23c5b8) by desbma)
- Improve network activity coverage ([d8aa8b5](https://github.com/desbma/shh/commit/d8aa8b53947606f4d2666834aeafe066fa02de33) by desbma)
- Dynamic IpAddressAllow ([4928a4c](https://github.com/desbma/shh/commit/4928a4ca81e5a4ed941a6e7ccc91d1dce6c7a6be) by desbma)
- Reorder options ([2f94302](https://github.com/desbma/shh/commit/2f94302149dea5a66fe7489f44cb7decf22fd8cb) by desbma)
- Greatly simplify SocketBindDeny handling ([25c9bf7](https://github.com/desbma/shh/commit/25c9bf730a435ec5156854eefef3a8aecaece65b) by desbma)
- IPv6 support for IPAddressAllow ([9dc0376](https://github.com/desbma/shh/commit/9dc0376ccb246ef511e3cad8987aa9d42646741f) by desbma)
- Make service reset block ([d95f533](https://github.com/desbma/shh/commit/d95f53397fb8cbec48eada4ab658574b923ac77a) by desbma)
- Add option to edit fragment before applying it ([a83c7ab](https://github.com/desbma/shh/commit/a83c7ab29f35a4b9e92a5d7f7e67f9961bc85d55) by desbma)

### <!-- 04 -->📗 Documentation

- FAQ: Fix typos + mention --merge-paths-threshold option ([9fc6412](https://github.com/desbma/shh/commit/9fc6412b026ca9e957d025e45e6003d043c084d2) by desbma)

### <!-- 05 -->🧪 Testing

- systemd-run: Add curl test ([8cecf59](https://github.com/desbma/shh/commit/8cecf59084077ac74e1e35695e24c9a5b5d27dbe) by desbma)
- Add ping IPv4 & IPv6 tests ([2c96a3f](https://github.com/desbma/shh/commit/2c96a3f8d78ef6f9063bef15b78ddc82450b2ef1) by desbma)

### <!-- 06 -->🚜 Refactor

- Mark unreachable code paths as such ([827e88c](https://github.com/desbma/shh/commit/827e88c6bf1480de626b48c15686c76f75f49dab) by desbma)
- Remove now unneeded CountableSetSpecifier ([975a9af](https://github.com/desbma/shh/commit/975a9af6c0a370fd133b678fe5961defd7cd7386) by desbma)
- Update panic macro usage ([4cc7328](https://github.com/desbma/shh/commit/4cc73288d9d25bc387a8ffa6f2143ada209753a8) by desbma)

---

## v2025.2.6

### <!-- 01 -->💡 Features

- Mkdir syscall ([f25364d](https://github.com/desbma/shh/commit/f25364d8a5e00f6e62b8efc1734f7b3d7fef5b01) by desbma)
- Track current dir ([1d0080b](https://github.com/desbma/shh/commit/1d0080b8c98ff65224e7f02f7276828e1099ceec) by desbma)
- Use current directory to resolve relative paths ([b486593](https://github.com/desbma/shh/commit/b486593667d9ce3f153469a059358e6230dfa605) by desbma)
- Log whole syscall when handling fails ([f8402d8](https://github.com/desbma/shh/commit/f8402d818d31afe68fe6b3a655162c21eb4a471e) by desbma)
- File system deny all + white list ([502ca9d](https://github.com/desbma/shh/commit/502ca9d451bfa72a40559f6503f0bbafaef8eb50) by desbma)
- Filesystem exception whitelist merging ([2263ab4](https://github.com/desbma/shh/commit/2263ab4e015c82cd6b8286d48626f81e59c72b50) by desbma)
- InaccessiblePaths systemd option (WIP) ([aa76500](https://github.com/desbma/shh/commit/aa765008c7ef121b7a44ae26a66fee112d64542d) by desbma)
- InaccessiblePaths dynamic whitelisting + auto merge options ([53a3c10](https://github.com/desbma/shh/commit/53a3c10757761b23429439dd1e06ea94cb6ad3fa) by desbma)
- Handle exec syscalls ([31814d2](https://github.com/desbma/shh/commit/31814d2eda9caff4352d0790eaba68f947f14380) by desbma)
- Support NoExecPaths systemd option + ExecPath whitelisting ([dbf32a4](https://github.com/desbma/shh/commit/dbf32a499aeabc45f30370e0215f5fe3822c31c1) by desbma)
- Handle PROT_EXEC memory mappings ([16345ae](https://github.com/desbma/shh/commit/16345aedbfb03e9ee9bf4e7bd214d800471dfb33) by desbma)
- Handle intermediate symlinks in all paths ([3015caf](https://github.com/desbma/shh/commit/3015caf90dd98b9abba7607aaa106d6853193193) by desbma)
- Parse ELF header to get dynamic linker interpreter ([6cef0c0](https://github.com/desbma/shh/commit/6cef0c0f0bc774e3fc9a1e10aaf845988afe8959) by desbma)
- Parse shebang to handle exec'd scripts ([1175415](https://github.com/desbma/shh/commit/11754157fb36b2c5c93e3b3820edc71dd3a2cbff) by desbma)
- Disable XxxPaths options if an exception for / makes them useless ([4c97afb](https://github.com/desbma/shh/commit/4c97afb274c31f80796391e3a52225f56939327c) by desbma)
- Auto remove .service suffix ([1355caf](https://github.com/desbma/shh/commit/1355caf3f50bc12ab568aebddc8ca809b2b28f7f) by desbma)
- Check for unsupported unit types ([dd09b00](https://github.com/desbma/shh/commit/dd09b00eb4b55cec1c3151b744c01470c82ef911) by desbma)
- Losslessly simplify paths lists when length is below threshold ([4307ef9](https://github.com/desbma/shh/commit/4307ef92fe8e36c6a3200ae928fde9f025e39398) by desbma)
- Prevent InaccessiblePaths/TemporaryFilesystem to be too easily disabled when / is read (WIP) ([407876f](https://github.com/desbma/shh/commit/407876f558178a2ed45d088f22fd2e2bf337861f) by desbma)
- Improve & re-enable InaccessiblePaths second option ([cdba2f5](https://github.com/desbma/shh/commit/cdba2f5c09742b25557ff42f96dd38390502c6ca) by desbma)
- Improve null effect removal ([f08380d](https://github.com/desbma/shh/commit/f08380d66cff98599c0cfdfd5ccceeecf409a3ef) by desbma)
- Split option effects EmptyPath/RemovePath ([5c6814c](https://github.com/desbma/shh/commit/5c6814cd71fcbc7bd99a065bc3c021dc6ae07e0d) by desbma)
- TemporaryFileSystem=xxx:ro & BindReadOnlyPaths=yyy support ([191fb61](https://github.com/desbma/shh/commit/191fb61c9ef399742b30e8d8abf96e84d42afd25) by desbma)
- Go deeper when whitelisting with TemporaryFileSystem ([d8b6ac5](https://github.com/desbma/shh/commit/d8b6ac51cd796913b56f4be4a6615cd9a6ca12e6) by desbma)
- Add systemd option whitelist for testing ([1bd3d49](https://github.com/desbma/shh/commit/1bd3d4963691dc6d272f6d6d8d551320b393e981) by desbma)
- Prevent duplicate BindPaths/BindReadOnlyPaths exceptions + add tests for InaccessiblePaths ([9c952b1](https://github.com/desbma/shh/commit/9c952b130f9713cc05cafcb18d7a039a58738dce) by desbma)
- Log 'systemd-analyze security' "exposure level" ([60d6309](https://github.com/desbma/shh/commit/60d63096240091f809537589c665cda7fa664120) by desbma)
- More explicit error reporting ([9d79ae3](https://github.com/desbma/shh/commit/9d79ae357c428e521e2996170f3176a5fc0a6dd9) by desbma)
- Improve markdown option list output ([f4f4c88](https://github.com/desbma/shh/commit/f4f4c88af499dbe41ad79464aa37c09e954f84a2) by desbma)
- Detect another case of nullified option effect ([5bd0532](https://github.com/desbma/shh/commit/5bd0532e962fe1246cedfe22df9030556ff8322e) by desbma)

### <!-- 02 -->🐛 Bug fixes

- Absolute path computation ([702ca50](https://github.com/desbma/shh/commit/702ca50f6274ec5cfbe53721193ed6f9779115ae) by desbma)
- Remove TODO obsolete comment ([0b20d4b](https://github.com/desbma/shh/commit/0b20d4b46a93ddb7594a29458f9bac9907a73824) by desbma)
- Test for char device defensively ([65e8c74](https://github.com/desbma/shh/commit/65e8c749ac87f1f057e519c852686599f61007c8) by desbma)
- Bind on port 0 handling ([d81a660](https://github.com/desbma/shh/commit/d81a660bdce40d04808f322f50864a0478bdc2df) by desbma)
- InaccessiblePaths handling of Create and Exec action whitelisting ([a358de9](https://github.com/desbma/shh/commit/a358de91fe9c2a035ccd40a568ca6125188439e3) by desbma)
- Open with O_RDONLY ([8014c66](https://github.com/desbma/shh/commit/8014c668392026cb9bef3059b9c4e97cdcff837c) by desbma)
- Don't follow symlinks when resolving paths ([de0d459](https://github.com/desbma/shh/commit/de0d459873ab6367df867c6bbf273692fef5baf2) by desbma)
- Open on symlink path ([096fc4f](https://github.com/desbma/shh/commit/096fc4f9436a7261996ba4beee79785fb3be8f88) by desbma)
- Reading /dev/kmsg requires CAP_SYSLOG ([2df9689](https://github.com/desbma/shh/commit/2df96898e74ffc8f96779d934e07f0ad2bd9efb7) by desbma)
- ProtectKernelLogs=true denies syslog ([39e2aa4](https://github.com/desbma/shh/commit/39e2aa44982faff79d3354b50e3445a38d9bb662) by desbma)
- PrivateDevices=true denies mknod and makes /dev noexec ([7f5b3d5](https://github.com/desbma/shh/commit/7f5b3d509dbbcda34b33d28b3f349b349d118707) by desbma)
- Per option element '-' prefix ([cc6fe8a](https://github.com/desbma/shh/commit/cc6fe8a1699e70c2edfd479b7ec947846e18dc3b) by desbma)
- Passing of network firewalling option ([6d1a361](https://github.com/desbma/shh/commit/6d1a3618d8d732f12906eb8761f4eab323d018ac) by desbma)
- Bind port 0 ([153531e](https://github.com/desbma/shh/commit/153531eb14ca400d8b27a06769a5a8014a613dba) by desbma)
- tests: Dmesg tests depending on system logs ([ed7f5cf](https://github.com/desbma/shh/commit/ed7f5cfa9d65380bb7fe073fd21057d1c88de10c) by desbma)
- Remove option negated by exception on / ([023bb61](https://github.com/desbma/shh/commit/023bb61dfdeb5ea33300d15d684244186ccd3f80) by desbma)
- Sort paths ([e2b75d5](https://github.com/desbma/shh/commit/e2b75d596d7a92cd9a83781e6612b5c8fcc99375) by desbma)
- Ensure paths in PATH env var are accessible ([877f62a](https://github.com/desbma/shh/commit/877f62a5b3f08ea9d37559fe482f07d008e8f392) by desbma)
- Don't make /proc or /run inaccessible ([e66e342](https://github.com/desbma/shh/commit/e66e34242622356a96bf836539615d9f2013e525) by desbma)
- Hide effect not incompatible with Create action ([5cce1b1](https://github.com/desbma/shh/commit/5cce1b128a1f03cb31cd199cf2e22706f8013fbb) by desbma)
- Null effect removal inverted test ([4c228df](https://github.com/desbma/shh/commit/4c228df231676ec6c2084f9d8f9df7349d663ab8) by desbma)
- Debian man page names ([4136bed](https://github.com/desbma/shh/commit/4136bed351390f6696ae3ce190ca4158bff96eeb) by desbma)

### <!-- 03 -->🏃 Performance

- Sort -> sort_unstable ([a3bfba5](https://github.com/desbma/shh/commit/a3bfba592cfd433c81d5cfe0a9effadeeae949ae) by desbma)
- More &'static str conversion ([5265b90](https://github.com/desbma/shh/commit/5265b90e2843124120c958733b0bc24d7b9e8fd0) by desbma)

### <!-- 04 -->📗 Documentation

- Add crates.io link & install instructions ([8986cfb](https://github.com/desbma/shh/commit/8986cfb8ab8d5444deb12e97d8cd335c4c47c249) by desbma)
- Improve description of --network-firewalling and --filesystem-whitelisting options ([4f5a867](https://github.com/desbma/shh/commit/4f5a86792d61a9862340c9cb54d648423bea96b4) by desbma)
- Add FAQ ([8ab785e](https://github.com/desbma/shh/commit/8ab785e4a979df5fc95211cd20640d1eecb9b0d2) by desbma)
- Comment typo ([71548b6](https://github.com/desbma/shh/commit/71548b6200c21da31149bfe027553b5ebfe85022) by desbma)
- Minor option description improvements ([e39c0bc](https://github.com/desbma/shh/commit/e39c0bc6978a1dfcb40de473fc7b078516618ee4) by desbma)
- README: Add shh run examples ([defe380](https://github.com/desbma/shh/commit/defe380d5ea1fd2b633a22d50ad258007a444521) by desbma)

### <!-- 05 -->🧪 Testing

- Fix sched_realtime integration test broken with Python 3.13 ([4fa9d25](https://github.com/desbma/shh/commit/4fa9d257bf49272396a90b45fb43c53f0e5771b1) by desbma)
- Add integration tests running systemd-run ([b59c63d](https://github.com/desbma/shh/commit/b59c63dbe862c39d18a353b99ab4da88cc7db0f3) by desbma)
- systemd-run: Log shh run options ([efa12eb](https://github.com/desbma/shh/commit/efa12eb8db7890218b5629dfb3394dff8bd4d94d) by desbma)
- Simplify mmap W+X commands ([2c83c5f](https://github.com/desbma/shh/commit/2c83c5fdc65e17019ad2c91706f30f92257faf59) by desbma)
- Fix passing file via /tmp ([b927803](https://github.com/desbma/shh/commit/b927803e775e4ac227f0003df8dbfd234c116134) by desbma)

### <!-- 06 -->🚜 Refactor

- Simplify OptionValue::List ([0e9a7fc](https://github.com/desbma/shh/commit/0e9a7fc932822857df5ffb6e41b4bd56160dd193) by desbma)
- Improve error handling for fd type conversions ([db420d3](https://github.com/desbma/shh/commit/db420d3e681bd3c7c5148713fc85db77b0a905cf) by desbma)
- Add convenience constructors for PathDescription ([f74cf59](https://github.com/desbma/shh/commit/f74cf59fd363e9ed7e1818790021add8a653a07e) by desbma)

### <!-- 09 -->🤖 Continuous integration

- Enable systemd-run integration tests ([c3b4d7f](https://github.com/desbma/shh/commit/c3b4d7fa72611eda4c0fab0b33684dd2e10ff269) by desbma)

### <!-- 10 -->🧰 Miscellaneous tasks

- Add cargo metadata & rename package to publish on crates.io ([1214fee](https://github.com/desbma/shh/commit/1214feeb6a2ffa5b1b74ea1f2be19e91b21f8fe7) by desbma)
- Lint ([3763bc0](https://github.com/desbma/shh/commit/3763bc072c422e1fc8288f7a3e46d47cba6b6ea0) by desbma)
- Update lints ([418bb2a](https://github.com/desbma/shh/commit/418bb2ac739a03e9ff34ab44eb9f9fd42012a234) by desbma)

---

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
