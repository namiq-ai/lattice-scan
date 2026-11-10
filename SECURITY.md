# Security

Report a vulnerability in lattice-scan, or anything that could make it leak a key or the host inventory, to **contact@namiq.io**. Please do not put the
details in a public issue first.

What the tool is meant to guarantee, so a report can say which one was broken:

- Only CVE ids, and the Lattice key if one is set, leave the machine. The inventory never does. Two other requests go to namiq.io and carry none of your data: a read of the public recent-CVE list together with its signature and certificate (two small static files beside it), and, once per run that read from the network, a "a scan ran" note with three fields (the command name, how it ended, and the number of reads as a band such as `1-5`). Turn the note off with `LATTICE_SCAN_NO_REPORT=1`. With no network or with `--offline` the note is kept in a small local file (50 at most, 30 days at most) and sent with the next online run; `--offline` itself makes no connection.
- Reading container images starts no container and pulls nothing: it creates a stopped container (`--pull never`, `--network none`, labelled `io.lattice-scan.run`), copies out the OS release file and the package database, and removes it. It keeps no environment values of an image except `*_VERSION`, and no serial numbers or UUIDs of the machine. Containers it made are removed when a run ends or is stopped, and the next run removes any a killed run left. Report anything that breaks these properties.
- The recent-CVE list is checked against namiq.io's signature. The certificate for the signing key must be signed by NamiQ's root key (built into the tool), valid for at most 90 days, and not older than the lowest serial this version accepts. A list with a wrong signature or certificate is not used; a list with none is read and labelled not verified.
- The key is never sent over cleartext http to a remote address, never followed to a redirect target, and never written to a log.
- Text that comes back from the network is treated as data: control characters are removed before it is printed or logged.
- The records directory is created private (mode 0700).
- The tool decides nothing about a host and never closes a finding by itself.

Supported: the latest release.
