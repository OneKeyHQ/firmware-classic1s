# CI pipeline
(Generated automatically by `tools/generate_ci_docs.py`. Do not edit by hand.)

It consists of multiple stages below, each having one or more jobs
Latest CI pipeline of master branch can be seen at [https://gitlab.com/satoshilabs/trezor/trezor-firmware/-/pipelines/master/latest](https://gitlab.com/satoshilabs/trezor/trezor-firmware/-/pipelines/master/latest)

## ENVIRONMENT stage - [environment.yml](https://github.com/trezor/trezor-firmware/blob/master/ci/environment.yml)
Connected with creating the testing image for CI.

Consists of **3 jobs** below:

### [.environment](https://github.com/trezor/trezor-firmware/blob/master/ci/environment.yml#L7)
Environment job builds the `ci/Dockerfile` and pushes the built docker image
into our GitLab registry. Since modifications of this Dockerfile are very rare
this is a _manual_ job which needs to be triggered on GitLab.
Almost all CI jobs run inside this docker image.

### [environment manual](https://github.com/trezor/trezor-firmware/blob/master/ci/environment.yml#L31)

### [environment scheduled](https://github.com/trezor/trezor-firmware/blob/master/ci/environment.yml#L35)

---
## PREBUILD stage - [prebuild.yml](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml)
Static checks on the code.

Consists of **6 jobs** below:

### [style prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L16)
Check the code for style correctness and perform some static code analysis.
Biggest part is the python one - using `flake8`, `isort`, `black`, `pylint` and `pyright`,
also checking Rust files by `rustfmt` and C files by `clang-format`.
Changelogs formats are checked.

### [common prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L25)
Check validity of coin definitions and protobuf files.

### [gen prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L32)
Check validity of auto-generated files.

### [editor prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L39)
Checking format of .editorconfig files.

### [release commit messages prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L46)
Checking the format of release commit messages.

### [changelog prebuild](https://github.com/trezor/trezor-firmware/blob/master/ci/prebuild.yml#L63)
Verifying that all commits changing some functionality have a changelog entry
or contain `[no changelog]` in the commit message.

---
## BUILD stage - [build.yml](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml)
All builds are published as artifacts so they can be downloaded and used.

Consists of **25 jobs** below:

### [core fw regular build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L20)
Build of Core into firmware. Regular version.
**Are you looking for Trezor T firmware build? This is most likely it.**

### [core fw regular debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L41)
Build of Core into firmware with enabled _debug_ mode. In debug mode you can
upload mnemonic seed, use debug link etc. which enables device tests. Storage
on the device gets wiped on every start in this firmware.

### [core fw regular production build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L54)

### [core fw btconly build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L77)
Build of Core into firmware. Bitcoin-only version.

### [core fw btconly debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L94)

### [core fw btconly production build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L117)

### [core unix regular build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L138)
Non-frozen emulator build. This means you still need Python files
present which get interpreted.

### [core unix regular asan build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L150)

### [core unix frozen regular build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L169)
Build of Core into UNIX emulator. Something you can run on your laptop.
Frozen version. That means you do not need any other files to run it,
it is just a single binary file that you can execute directly.

### [core unix frozen btconly debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L186)
Build of Core into UNIX emulator. Something you can run on your laptop.
Frozen version. That means you do not need any other files to run it,
it is just a single binary file that you can execute directly.
See [Emulator](../core/emulator/index.md) for more info.
Debug mode enabled, Bitcoin-only version.

### [core unix frozen btconly debug asan build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L202)

### [core unix frozen debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L225)
Build of Core into UNIX emulator. Something you can run on your laptop.
Frozen version. That means you do not need any other files to run it,
it is just a single binary file that you can execute directly.
**Are you looking for a Trezor T emulator? This is most likely it.**

### [core unix frozen debug asan build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L238)

### [core unix frozen debug build arm](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L254)

### [core macos frozen regular build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L276)

### [crypto build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L301)
Build of our cryptographic library, which is then incorporated into the other builds.

### [legacy fw regular build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L330)

### [legacy fw regular debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L346)

### [legacy fw btconly build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L363)

### [legacy fw btconly debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L382)

### [legacy emu regular debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L403)
Regular version (not only Bitcoin) of above.
**Are you looking for a Trezor One emulator? This is most likely it.**

### [legacy emu regular debug asan build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L418)

### [legacy emu regular debug build arm](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L436)

### [legacy emu btconly debug build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L462)
Build of Legacy into UNIX emulator. Use keyboard arrows to emulate button presses.
Bitcoin-only version.

### [legacy emu btconly debug asan build](https://github.com/trezor/trezor-firmware/blob/master/ci/build.yml#L479)

---
## TEST stage - [test.yml](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml)
All the tests run test cases on the freshly built emulators from the previous `BUILD` stage.

Consists of **33 jobs** below:

### [core unit python test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L15)
Python unit tests, checking core functionality.

### [core unit rust test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L24)
Rust unit tests.

### [core unit asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L33)

### [core device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L54)
Device tests for Core. Running device tests and also comparing screens
with the expected UI result.
See artifacts for a comprehensive report of UI.
See [docs/tests/ui-tests](../tests/ui-tests.md) for more info.

### [core device asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L83)

### [core btconly device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L102)
Device tests excluding altcoins, only for BTC.

### [core btconly device asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L122)

### [core monero test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L143)
Monero tests.

### [core monero asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L162)

### [core u2f test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L184)
Tests for U2F and HID.

### [core u2f asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L203)

### [core fido2 test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L221)
FIDO2 device tests.

### [core fido2 asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L244)

### [core click test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L264)
Click tests.
See [docs/tests/click-tests](../tests/click-tests.md) for more info.

### [core click asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L292)

### [core upgrade test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L313)
Upgrade tests.
See [docs/tests/upgrade-tests](../tests/upgrade-tests.md) for more info.

### [core upgrade asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L332)

### [core persistence test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L354)
Persistence tests.

### [core persistence asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L370)

### [core hwi test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L388)

### [crypto test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L406)

### [legacy device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L437)

### [legacy asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L464)

### [legacy btconly test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L476)

### [legacy btconly asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L496)

### [legacy upgrade test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L511)

### [legacy upgrade asan test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L530)

### [legacy hwi test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L551)

### [python test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L570)

### [python support test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L589)

### [storage test](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L599)

### [core unix memory profiler](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L623)

### [connect test core](https://github.com/trezor/trezor-firmware/blob/master/ci/test.yml#L647)

---
## TEST-HW stage - [test-hw.yml](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml)

Consists of **5 jobs** below:

### [hardware core regular device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml#L25)
[Device tests](../tests/device-tests.md) that run against an actual physical Trezor T.
The device needs to have special bootloader, found in `core/embed/bootloader_ci`, that
makes it possible to flash firmware without confirmation on the touchscreen.

All hardware tests are run nightly on the `master` branch, as well as on push to branches
with whitelisted prefix. If you want hardware tests ran on your branch, make sure its
name starts with `hw/`.

Currently it's not possible to run all regular TT tests without getting into
a state where the micropython heap is too fragmented and allocations fail
(often manifesting as a stuck test case). For that reason some tests are
skipped.
See also: https://github.com/trezor/trezor-firmware/issues/1371

### [hardware core btconly device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml#L54)
Also device tests on physical Trezor T but with Bitcoin-only firmware.

### [hardware core monero test](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml#L83)

### [hardware legacy regular device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml#L113)
[Device tests](../tests/device-tests.md) executed on physical Trezor 1.
This works thanks to [tpmb](https://github.com/mmahut/tpmb), which is a small arduino
device capable of pushing an actual buttons on the device.

### [hardware legacy btconly device test](https://github.com/trezor/trezor-firmware/blob/master/ci/test-hw.yml#L137)
Also device tests on physical Trezor 1 but with Bitcoin-only firmware.

---
