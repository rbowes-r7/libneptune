This repository is a collection of exploits and proofs of concept for
vulnerabilities in Rocket Software's UniRPC server (and related services) that
is installed along with the UniData server software. We tested UniData version
8.2.4.3001 for Linux, downloaded at the start of January 2023.

The UniRPC service typically listens on TCP port 31438, and runs as root. We
tested everything with a default installation (ie, no special configuration).
We've provided checksums of all the files below, to make it easier to identify
the vulnerable software binaries.

To avoid duplicating information, full descriptions and documentation on the
vulnerabilities is in
[this blog post](https://www.rapid7.com/blog/post/2023/03/29/multiple-vulnerabilities-in-rocket-software-unirpc-server-fixed)
