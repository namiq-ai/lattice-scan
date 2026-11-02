# Security

Report a vulnerability in lattice-scan, or anything that could make it leak a key or the host inventory, to **contact@namiq.io**. Please do not put the
details in a public issue first.

What the tool is meant to guarantee, so a report can say which one was broken:

- Only CVE ids, and the Lattice key if one is set, leave the machine. The inventory never does.
- The key is never sent over cleartext http to a remote address, never followed to a redirect target, and never written to a log.
- Text that comes back from the network is treated as data: control characters are removed before it is printed or logged.
- The records directory is created private (mode 0700).
- The tool decides nothing about a host and never closes a finding by itself.

Supported: the latest release.
