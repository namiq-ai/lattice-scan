# The LATTICE INVENTORY v1 block

What `lattice-scan inventory --share` prints, and what the Lattice Analyst reads. The tool and the reader are written to this definition independently.

```
LATTICE INVENTORY v1
tool: lattice-scan 0.4.8
taken: 2026-11-08
os: Ubuntu 26.04.1 LTS
kernel: 7.0.0-41-cix
arch: aarch64
counts: packages 2748, snaps 13, images 7, listening 9
feed: read 2026-11-08 (65 entries)
items: 77 of 2769 shown (kernel, listening, CISA-feed matches, images, snaps, curated, in that order)
--
kernel 7.0.0-41-cix why=kernel
pkg openssh-server 1:10.0p1-5ubuntu5 why=listen:tcp/22
pkg bind9-dnsutils 1:9.20.24-1ubuntu0.5 why=cisa:CVE-2015-5477
image redis:alpine why=image
snap firefox 159.0.1-1 why=snap
pkg openssl 3.4.1-1 why=curated
--
listen tcp all:22 owner=openssh-server
listen tcp loopback:5432
posture: firewall=ufw:active,nftables:inactive ssh.passwordauthentication=yes ssh.permitrootlogin=no
end
```

Rules: UTF-8, LF, under 12 KB and 150 lines. The header is exactly these keys in this order (`os`, `feed` and `items` values may hold spaces and commas). After the first `--`, one item per line: the first word is the
kind (`kernel`, `pkg`, `snap`, `image`), then the name, then the version (not for an image), then `why=` with `kernel`, `listen:PROTO/PORT[,...]`, `cisa:CVE-ID`, `image`, `snap` or `curated`. After the second `--`,
`listen PROTO BIND:PORT [owner=NAME]` where BIND is `all`, `loopback` or `address` (the address itself is never printed), then one `posture:` line with `key=value` pairs, then `end`. A line a reader does not know is skipped
and counted. A name or version holds only letters, digits and `. + : ~ _ -`; a path, an address, a user name or a second word is dropped by the tool.

Order of selection when the block is full: the kernel, what owns a listening socket, what the CISA list may concern, images, snaps, curated software (at most three of a family, at most 60 in all, never documentation,
data, development or completion packages). Curated software is a reviewed list in `src/lattice_scan/share.py`.
