# Sources and dependencies

New implementation copyright 2026 imaflyfish, GPL-2.0-only (see LICENSE).
The switch-flattening approach follows DumpA1n's MIT-licensed unflatten64. Its
copyright notice is retained in `licenses/unflatten64-MIT.txt`.

| Dependency | Version | Applicable library license |
|---|---|---|
| Capstone | 5.0.9 | BSD-3-Clause |
| Unicorn | 2.1.4 | GPL-2.0; see its component notices and COPYING files |
| yaml-cpp | 0.9.0 | MIT |
| nlohmann/json | 3.12.0 | MIT |
| libgcrypt | 1.12.4 | LGPL-2.1-or-later |
| libgpg-error | 1.61 | LGPL-2.1-or-later |

Exact source locations are in `dependencies.lock.json`; copied license texts are
in `licenses/`. Package tools can have additional GPL notices distinct from their
shared library's license. Dependencies are installed separately rather than
vendored; final runtime paths will be recorded with the delivered binary.

The digest dependency was changed from OpenSSL 3 to libgcrypt during development
to avoid combining Apache-2.0 code with GPL-2.0-only Unicorn components. The license
compatibility basis is documented by the
[GNU license list](https://www.gnu.org/licenses/license-list.en.html#apache2).
SHA-256 still binds complete snapshots and candidate images; the hash values are
checked against known vectors and prior snapshot outputs.

LLVM/LLD, sanitizers, libFuzzer and IDA are development/host tools. They are not
redistributed with the native program. The neutral assembly source is new project
code. Existing user databases and third-party target binaries are not test fixtures.
