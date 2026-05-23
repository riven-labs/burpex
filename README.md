# burpex

Reads a Burp Suite project file (`.burp`) and turns it into JSON so you can
pipe the contents into your own tooling — request replay, finding triage,
scope reviews, whatever.

> **This is ongoing reverse-engineering work, not a finished tool.** Burp's
> project format is undocumented and changes between versions. Plenty of
> records are still classified as `unknown`, and severity/confidence aren't
> attached to issues yet. What's here is enough to be useful, not enough
> to be done.

## What it can do today

- Walk the framed-record container that holds the whole project.
- Decode HTTP requests and responses, including gzip / br / deflate /
  chunked bodies. Binary bodies come back as base64 instead of garbled text.
- Group request, response, and the sitemap path into one HTTP transaction.
- Classify each large "state blob" as scanner config, scan issues, scope,
  live tasks, sitemap, or unknown.
- Pull out scope rules, file-extension filters, scanner parameter names,
  scan issue text, flagged cookies, leaked emails, and Luhn-valid card
  numbers found in traffic.
- Map the file layout: fixed header, extended header, frame runs, trailers,
  zero-padded tail.

It runs end-to-end in ~1.3 seconds on a 1 GB project file on a single thread.

## Install

```
cargo install --git https://github.com/riven-labs/burpex
```

Pre-built binaries for Linux / macOS / Windows ship with each release.

## CLI

```
burpex info <file>           header + stats + project summary
burpex layout <file>         file layout (header, runs, trailers, tail)
burpex walk <file>           one JSON line per frame (raw)
burpex http <file>           one JSON line per HTTP message
burpex transactions <file>   one JSON line per request+response+sitemap path
burpex extract <file> -o     full extraction to a single JSON document
burpex blobs <file> -o dir/  dump every text/JSON/state-blob payload
```

Flags shared across the streaming commands: `--limit N`, `--body-cap N`.

## Library

```rust
use burpex::BurpProject;

let proj = BurpProject::open("project.burp")?;

for txn in proj.transactions().with_body_cap(8 * 1024).iter() {
    if let (Some(req), Some(resp)) = (&txn.request, &txn.response) {
        println!("{} {} -> {}",
            req.method.as_deref().unwrap_or("?"),
            req.path.as_deref().unwrap_or("?"),
            resp.status.unwrap_or(0));
    }
}
```

Two `examples/` programs ship with the crate:

- `replay_targets` — turn every request into a `curl` line.
- `issues_to_csv` — dump scan findings as CSV.

```
cargo run --release --example replay_targets -- path/to/project.burp
cargo run --release --example issues_to_csv -- path/to/project.burp
```

## What still isn't decoded

- The 1-byte type tags before UTF-16BE strings inside state blobs
  (`t` = text, `d` = rule, `s` = short, ...). Strings come out clean but
  aren't yet typed.
- Severity, confidence, and per-issue request/response IDs are still loose
  in the `affected_urls` / `flagged_cookies` lists rather than attached to
  each `ScanIssue` record.
- A pile of state-blob trailers classified as `unclassified` — they hold
  variable-shape metadata I haven't mapped yet.
- Anything stored beyond depth 4 in nested state blobs (~12% of HTTP
  messages on large projects).

The `burpex walk` and `burpex layout` subcommands surface the bytes we
don't understand yet — they're the levers for pushing the RE further.

## Build from source

```
git clone https://github.com/riven-labs/burpex
cd burpex
cargo build --release
cargo test --release
```

## License

MIT.
