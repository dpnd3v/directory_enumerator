# Directory Enumerator

Async HTTP directory and file brute-force with smart SPA/catch-all detection.
Filters false positives via 3-probe baseline fingerprinting. Returns status,
size, content-type and redirect per path. Includes CDN detection, geolocation
and IP info on the target.

## Requirements

```
pip install aiohttp
```

## Usage

```bash
python dir_enum.py <url> [options]

python dir_enum.py https://example.com
python dir_enum.py https://example.com -e .php .html .bak
python dir_enum.py https://example.com --rps 100 -o results.txt
python dir_enum.py https://example.com --idle 30 -c 200
```

## Wordlist

Place `dirs.txt` in the same directory as the tool — loaded automatically.
To use a different file:

```bash
python dir_enum.py https://example.com -w /path/to/custom.txt
```

## Options

| Flag | Default | Description |
|---|---|---|
| `-w` | `dirs.txt` | Wordlist path |
| `-e` | — | Extensions to append e.g. `-e .php .html .bak` |
| `-c` | `200` | Concurrent async requests |
| `--rps` | `150` | Requests per second (50 = safe, 500 = fast) |
| `-t` | `5.0` | Per-request timeout (s) |
| `--idle` | `60` | Stop after N seconds with no new hits |
| `-o` | — | Save output to file |
| `--ua` | `DirEnum/1.0` | Custom User-Agent |

## Output

```
URL                               STATUS   TIPO       SIZE    CONTENT-TYPE   REDIRECT
--------------------------------------------------------------------------------------
https://example.com/admin         403      FORBIDDEN  1842    text/html      -
https://example.com/api/v1        200      FOUND      512     application/json  -
https://example.com/backup.zip    200      FOUND      94821   application/zip   -
https://example.com/login         301      REDIRECT   0       text/html      /login/
```

## Status legend

| Status | Label | Meaning |
|---|---|---|
| 200/201/204 | FOUND | Path exists and is accessible |
| 301/302/307/308 | REDIRECT | Redirects — check REDIRECT column |
| 401 | AUTH | Exists but requires authentication |
| 403 | FORBIDDEN | Exists but access is denied |
| 405 | METHOD | Endpoint exists, wrong HTTP method |
| 500/503 | ERROR | Server-side error |

## Baseline detection

Before scanning, the tool sends 3 requests to guaranteed-nonexistent paths
and builds a fingerprint of the server's soft-404 response. This handles:

- **Static soft-404** — same body every time, filtered by hash
- **SPA / React / Next.js** — dynamic HTML with variable size, filtered by content-type + size range
- **Catch-all** — server returns 200 on everything, filtered by status + content-type + size threshold

Without this, tools like gobuster and ffuf return hundreds of false positives
on modern single-page applications.
