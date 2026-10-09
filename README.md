# bandaid

>I wish I could put a band-aid on my heart, too.

>...You put one on mine.

## Usage

```
Usage of bandaid:
      --addr-var-name string       generated address variable name
      --cacert string              CA certificate file
      --cert string                client certificate file
      --default-str string         generated default string
  -d, --dry-run                    fetch and generate once without running as a service
  -t, --fetch-timeout duration     set fetch HTTP timeout (default 10s)
  -o, --geofile string             generated geo file path
      --geofile-mode string        set mode of created geofile (default "644")
  -h, --help                       show this help and exit
      --key string                 client key file
  -l, --log-level string           log level: none, error, warn, info, debug or a numeric level (default "info")
  -m, --max-report-bytes int       maximum accepted report size in bytes (default 33554432)
  -x, --post-exec string           command and args to run after geo file update (executed directly, not through a shell)
  -i, --update-interval duration   geo file update interval (default 1m0s)
  -u, --url string                 report URL to fetch
  -n, --var-name string            generated variable name (default "$geo")
  -v, --version                    print version and exit
  -w, --whitelist string           whitelist targets delimited with commas
```

### Example

```bash
bandaid -u https://report.example.com/report.json \
        --cacert ./ca.crt \
        --cert ./client.crt \
        --key ./client.key \
        -w 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
        -d
```

## Report format


```json
{
  "findings": [
    {
      "target": "114.5.1.4",
      "reasons": ["reason1", "reason2"]
    },
    {
      "target": "2000:aaaa::/64",
      "reasons": ["reason3"]
    }
  ]
}
```

## Output format

```
geo [${addr-var-name}] ${var-name} {
    [default "${default-str}";]
    114.5.1.4/32 "reason1:reason2";
    2000:aaaa::/64 "reason3";
}
```

## Build

```bash
make
```

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License Version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License Version 3 along with this program. If not, see <https://www.gnu.org/licenses/>. 
