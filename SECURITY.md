# Security policy

Please do not report security vulnerabilities in a public issue. Use the repository **Security** tab and choose **Report a vulnerability** to create a private GitHub security advisory. Private vulnerability reporting is enabled for this repository.

Include the affected version or commit, impact, a minimal reproduction, and a suggested fix when available. Redact credentials, tokens, personal data, and private URLs. If the Security tab does not offer private reporting, do not post sensitive details publicly; contact the repository maintainers through GitHub and provide only a safe pointer to the affected area.

## Out of scope: vendor binaries and credentials

This repository publishes our own interoperability code only. The following are
**out of scope**, and a pull request, patch or issue attachment that adds any of
them is rejected without review:

- **Vendor binaries** — firmware images and release containers (`.swu`), extracted
  filesystems, vendor applications and libraries, and anything rebuilt from them.
  They are not redistributable here, and nothing under `firmware/` ships.
- **Vendor documentation** — manuals, help text, and screenshots of either.
- **Decompiled or reconstructed vendor material** — decompiler output, function
  and string ledgers, and reconstructed sources derived from vendor binaries.
- **Credential material** — tokens, API keys, passwords, password hashes,
  private keys, certificates carrying private key material, and capture files or
  recordings that contain any of the above.

The export gate refuses these paths and patterns by name, and review starts from
that refusal, so submitting one costs a reviewer a rejection rather than a
discussion. Report a suspected leak of any of the above through the Security tab
instead, and do not paste the value itself into an issue or a pull request.
