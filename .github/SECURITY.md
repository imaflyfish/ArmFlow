# Security reporting

For a sensitive report, use GitHub's [private vulnerability reporting](https://github.com/imaflyfish/ArmFlow/security/advisories/new).
The private reporting channel is enabled for this repository. Ordinary correctness
bugs can be filed as public issues with private information removed. If the private
form is unavailable, open a minimal issue asking for a reporting channel without
including sensitive details.

Reports are handled on a best-effort basis; no response deadline or maintained
binary-release support window is promised. Identify the exact commit and compare
with the current default branch where practical.

ArmFlow reads images, configurations and staged artifacts. Its CLI returns
separate snapshots; the IDA adapter can write database bytes and graph metadata.
Reports about malformed-input handling, bypassed candidate-verification gates,
unrequested writes or failed restoration are welcome.

Include the exact commit, OS/tool versions, command or adapter operation, minimal
shareable fixture/configuration and expected versus observed changes. For IDA,
include its version and whether the problem affects bytes, graph state or rollback.
Use a disposable database copy when reproducing an issue.

Configured command oracles and trace commands execute external programs with the
caller's privileges; they are not a sandbox. Finite examples and bounded emulation
are not a proof of equivalence for every input. Incorrect rewrites are still worth
reporting within these limits. See [configuration](../docs/CONFIG.md) and the
[IDA guide](../integrations/ida/README.md).
