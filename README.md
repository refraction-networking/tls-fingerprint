# tls-fingerprint

This tool observes TLS Client Hello messages, and creates unique fingerprints to track the frequency and distribution of messages seen. When run on a sufficient traffic source, this tool allows researchers to learn which client hello messages are most popular.

Knowing statistics of common ClientHello messages can help inform design decisions in relevant software, such as webservers. In addition, this also enables censorship circumvention tools to be able to keep track of which TLS client implementations should be mimicked, and if their tool has a unique fingerprint

## Installing

```
git clone --recurse-submodules https://github.com/sergeyfrolov/tls-fingerprint/
cd tls-fingerprint/PF_RING
make
cd ../
make
```

## Running

### Lite version

 * Writes to stdout.
 * Does not require PF_RING.
 * Useful to get fingerprint ID of your application to compare it against our db later.

Simply run `./rust-src/target/release/tls_fingerprint $INTERFACE`

### PF_RING version

 * Writes to PostgreSQL.
 * Requires PF_RING.
 * Used to collect a database of fingerprint on a high-bandwidth taps. Was tested on 10Gbps links.

You'll need to run `zbalance_ipc` from PF\_RING on the interface you want to capture. (See
PF\_RING for how to configure and set up using zero-copy PF\_RING and zbalance clusters)
Then, you can run `./tls-fingerprint -c $CLUSTER_NUM -n $CORES` for the cluster number and
number of cores to run on (parameters also passed to `zbalance_ipc`

