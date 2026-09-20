# Task 3 — `cloudscan`: multi-cloud open-firewall scanner

A Go CLI that authenticates to AWS, GCP and Azure, fetches every firewall /
security group / NSG rule, reports the ones that admit inbound traffic from
`0.0.0.0/0`, and prints the result as JSON in the schema the brief specifies.

```bash
go build -o cloudscan .

./cloudscan -azure-subscriptions <SUBSCRIPTION> -gcp-projects <PROJECT>                                   # every provider, credentials from the default chains
./cloudscan -providers aws,gcp                # a subset
./cloudscan -fixture testdata/fixture.json    # offline demo, no credentials required
./cloudscan -fail-on-findings -out report.json
```

Requires Go 1.25 or newer (the minimum for `azidentity` v1.14).

## Output

`./cloudscan -fixture testdata/fixture.json` produces exactly the brief's
schema — also kept in `sample-output.json`:

```json
{
  "aws": {
    "security_groups": [
      {
        "id": "sg-12345678",
        "name": "open-sg",
        "insecure_rules": [
          { "protocol": "tcp", "port": 8080, "source": "0.0.0.0/0" },
          { "protocol": "udp", "port": 123, "source": "0.0.0.0/0" }
        ]
      }
    ]
  },
  "gcp": {
    "firewall_rules": [
      {
        "name": "allow-all",
        "network": "default",
        "insecure_rules": [
          { "protocol": "icmp", "port": "all", "source": "0.0.0.0/0" }
        ]
      }
    ]
  },
  "azure": {
    "nsgs": [
      {
        "id": "/subscriptions/xxxx/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg",
        "name": "open-nsg",
        "insecure_rules": [
          { "protocol": "*", "port": "*", "source": "0.0.0.0/0" }
        ]
      }
    ]
  }
}
```

A golden test (`main_test.go`) asserts this byte for byte, so a change that
breaks the contract fails CI rather than surfacing downstream.

## How it works

```
main.go              flags, concurrency, exit codes, JSON output
internal/scanner/    the report model and ALL detection logic (no SDK imports)
internal/providers/  one file per cloud: SDK calls translated into the model
                     + fixture.go, which replays recorded API shapes
```

The layering is the point: `internal/scanner` imports nothing from any cloud
SDK, so every detection decision is unit-testable without credentials, and the
JSON contract lives in exactly one place. Providers do I/O and translation, and
nothing else.

| Cloud | API call | What is examined |
|---|---|---|
| AWS | `ec2:DescribeSecurityGroups` (paginated, per region, regions discovered with `ec2:DescribeRegions`) | `IpPermissions` — ingress only. `IpRanges` **and** `Ipv6Ranges` |
| GCP | `compute.firewalls.list` (paginated, per project) | Ingress, non-disabled, `allowed` rules whose `sourceRanges` include the internet |
| Azure | `Microsoft.Network/networkSecurityGroups` list-all (per subscription) | `securityRules` where direction is Inbound and access is Allow, built-in defaults with `-azure-default-rules` |

### What counts as "open to the internet"

The test is a **zero-length prefix**, not a string comparison
(`internal/scanner/detect.go`):

- `0.0.0.0/0` and `::/0` — the only CIDRs covering every address. IPv6 matters:
  an IPv4-only check is the standard way to miss a wide-open group.
- Azure's non-CIDR spellings: `*`, `Any`, and the `Internet` service tag. Most
  open NSG rules in the wild use these, so matching only the literal
  `"0.0.0.0/0"` would miss them.

Deliberately **not** flagged, each for a reason the report would otherwise be
wrong about:

| Not flagged | Why |
|---|---|
| `0.0.0.0/1`, `10.0.0.0/8` | Wide but bounded. Worth a finding in a real programme, but a *different* finding with a different severity, conflating them makes the tool unusable as a merge gate. One-line change in `IsInternetSource` if you want it |
| Disabled GCP firewall rules | A disabled rule enforces nothing, reporting it trains people to ignore output |
| Egress rules | Outbound to the internet is normal and out of scope here |
| Azure `Deny` rules, Outbound rules | A deny from the internet is the control, not the problem |
| `VirtualNetwork`, `AzureLoadBalancer` tags | Internal, not internet |
| Google health-check ranges `35.191.0.0/16`, `130.211.0.0/22` | Required for load-balanced backends to work, flagging them produces noise that buries the real findings |

Each of these is a test case in `internal/scanner/detect_test.go` and
`eval_test.go`.

### Provider quirks the evaluation handles

- **AWS** `IpProtocol: "-1"` means every protocol, and then `FromPort`/`ToPort`
  are absent rather than `0-65535`.
- **GCP** omits `ports` to mean every port, and a port entry may itself be a
  range (`"8000-9000"`).
- **Azure** expresses sources and ports in both singular and plural fields
  (`sourceAddressPrefix` / `sourceAddressPrefixes`), and its defaults
  (`AllowVnetInBound`, `DenyAllInBound`) must not be mistaken for findings.

### Output schema notes

- **`port` is a number or a string.** The brief's example uses `8080` (number)
  and `"*"`/`"all"` (strings), so `Port` marshals as whichever the value calls
  for. A full range collapses to the wildcard so providers stay comparable.
- **GCP's all-ports case renders `"all"`**, matching both the brief's example and
  GCP's own API vocabulary (`IPProtocol: "all"`), AWS and Azure use `"*"`,
  matching theirs.
- **Unrequested providers are omitted**, not emitted as empty objects, an empty
  object reads as "scanned, clean", which would be a lie.
- **`region` / `project`** appear on a finding only when more than one was
  scanned (a security group ID is unique per region, not globally). With a
  single scope the output is exactly the brief's schema.
- `-include-metadata` adds a `scan_metadata` object with counts, timings and
  per-provider errors. It is off by default so the default output matches the
  required schema byte for byte.

## Operational behaviour

- **Partial failure is not total failure.** An opted-out AWS region or a missing
  Azure role records a `ScanError` and the other scopes still scan. Errors always
  go to stderr and set exit code 3, so a failed provider can never be read as a
  clean result — the failure mode that makes a security scanner worse than none.
- **Providers run concurrently**, each under one overall `-timeout` deadline.
- **Credentials are never flags.** Each SDK's default chain is used (env, shared
  config, SSO, workload/managed identity, instance role). A key on an argv line
  ends up in shell history and in `ps` output.
- **Read-only by construction.** The GCP client requests
  `compute.readonly`, no provider path calls a mutating API.
- **`-out` files are created 0600.** A findings report is a map of where an
  account is weakest.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, nothing to report (or findings without `-fail-on-findings`) |
| 1 | Insecure rules found, with `-fail-on-findings`, the CI gate |
| 2 | Could not run (bad flags, unwritable output) |
| 3 | A provider failed, the report holds partial results |

### Least-privilege permissions to run it

| Cloud | Grant |
|---|---|
| AWS | `ec2:DescribeSecurityGroups`, `ec2:DescribeRegions` (or `SecurityAudit`) |
| GCP | `roles/compute.networkViewer` |
| Azure | `Reader` on the subscription |

## Tests

```
$ go test ./... -cover
ok  cloudscan                     coverage: 35.0% of statements
ok  cloudscan/internal/scanner    coverage: 78.0% of statements
```

Coverage is concentrated where it matters: the detection layer. The provider
files are thin SDK translation and are exercised end-to-end through
`testdata/fixture.json`, which is run through the *same* evaluation functions
the live providers call — the fixtures include compliant resources precisely so
that a filtering bug fails the test rather than passing silently.

`go vet ./...` and `gofmt -l .` are clean.
