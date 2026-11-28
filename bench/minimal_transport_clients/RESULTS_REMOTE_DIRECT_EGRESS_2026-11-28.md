# remote direct origin egress control

Date: 2026-11-28

## Purpose and limits

This is a direct download from the remote node host to the public OVH test file. It
provides an egress/origin control for the pending remote HY2 and REALITY
measurements. It does **not** traverse a Chimera or official proxy client, so
it is not a proxy throughput result and does not measure the client-to-remote node
path.

The test downloaded the same 100 MiB object three times with `curl`, TLS
certificate verification enabled, and the body discarded locally. All three
responses were HTTP 200 and reported exactly 104,857,600 downloaded bytes;
TLS verification returned `0` in every trial.

## Results

| Trial | Time | Curl rate | Application rate |
| ---: | ---: | ---: | ---: |
| 1 | 5.322 s | 19.70 MB/s | 157.62 Mbit/s |
| 2 | 5.238 s | 20.02 MB/s | 160.15 Mbit/s |
| 3 | 6.532 s | 16.05 MB/s | 128.43 Mbit/s |
| Median | 5.322 s | 19.70 MB/s | 157.62 Mbit/s |

The Mbit/s column converts curl's decimal bytes/second to decimal bits/second.
The three-trial range is 128.43–160.15 Mbit/s, so this small control shows
noticeable variation and is not a stable capacity ceiling. The exact source
bytes and TLS result are retained in the command output from the test run;
credentials and endpoint addresses are not part of this report.

The local management name `remote node` resolved to a private address routed over
`tun0`. A 20-packet ICMP probe on that path received all packets, with 0.083 ms
average RTT (0.035–0.200 ms). This characterizes the management/overlay route;
it does not prove that a proxy benchmark used the same endpoint or route.

## Interpretation

The remote node host can currently complete a direct, byte-counted download from the
chosen origin at roughly 158 Mbit/s median. The earlier proxy requests did not
complete their application payload, so this baseline cannot identify whether
the limiting or failing stage is the HY2/REALITY client, proxy data path,
server-side target connection, or a path-specific policy. Do not calculate a
proxy efficiency ratio until a full-size proxied transfer passes content
verification against the same origin.

The earlier, separate proxy smoke attempts are retained as failures rather
than throughput samples:

- HY2 authentication to the active remote node inbound succeeded, but the external
  HTTPS request through the local SOCKS bridge ended with an unexpected EOF;
  the client reported that the peer stopped the send path.
- The REALITY/VLESS request to the external test object timed out after 15
  seconds without a completed application response.
- Attempts to send traffic to a remote node loopback or private-interface source were
  rejected by the inbound's private-address egress policy. Those targets do
  not form a valid proxy benchmark topology.

These observations do not identify the cause of the public-target failures.

Next, run a small verified HTTP/TCP smoke through each remote node inbound with both a
minimal Chimera client and the matching official client. Only after that passes
should the test repeat the download for throughput and resource measurements.
