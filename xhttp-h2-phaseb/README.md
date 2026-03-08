# xhttp-h2-phaseb (tokio + hyper, H2C)

Runnable minimal demo implementing:
- **stream-one**: single HTTP/2 request carries duplex stream (POST body uplink, response body downlink)
- **Phase B**: **stream-down + packet-up** with sessionId + seq reorder (UploadQueue)

This is **H2C prior-knowledge** (cleartext HTTP/2). Use the provided clients.

## Docs

- Request flow and sequence diagrams:
  [docs/20260309-xhttp-h2-phaseb-sequence-diagrams.md](/home/si/Desktop/mfsga/Chimera_Client/docs/20260309-xhttp-h2-phaseb-sequence-diagrams.md)
- Xray/XHTTP terminology mapping:
  [docs/20260309-xhttp-h2-phaseb-xray-term-mapping.md](/home/si/Desktop/mfsga/Chimera_Client/docs/20260309-xhttp-h2-phaseb-xray-term-mapping.md)
- Proposed Chimera xhttp config draft:
  [docs/20260309-xhttp-config-draft.md](/home/si/Desktop/mfsga/Chimera_Client/docs/20260309-xhttp-config-draft.md)

## Run

Terminal 1:
```bash
cargo run --bin server
```

Terminal 2 (stream-one):
```bash
cargo run --bin client_stream_one
```

Terminal 3 (Phase B split):
```bash
cargo run --bin client_split
```

### Phase B behavior
- Client generates a random `sessionId`
- Opens `GET /xhttp/<sessionId>` for downlink (prints server echo)
- Reads stdin lines; each line is sent as `POST /xhttp/<sessionId>/<seq>` (seq starts at 0)
- Server reorders by seq and streams reconstructed uplink bytes back on the GET response body.

Notes:
- This demo keeps things minimal: path placement only; no padding/headers/cookies; no stream-up mode.
- Defaults match Xray's typical values:
  - max_each_post_bytes = 1_000_000
  - max_buffered_posts = 30
  - session_ttl = 30s
