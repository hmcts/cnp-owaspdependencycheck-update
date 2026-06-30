# cnp-owaspdependencycheck-update

Pipeline for automating owasp dependency check updates to Azure DB.

## Pipelines

| File | Purpose |
| ---- | ------- |
| `azure-pipelines.yml` | Production: Flyway-migrates the shared cached OWASP DB then refreshes the NVD data from the blob mirror (every 3h). |
| `azure-pipelines-sbox.yml` | Sandbox equivalent of the production pipeline. |
| `azure-pipelines-nvd-mirror.yml` | DTSPO-32997 Option B: builds the NVD datafeed and publishes it to Blob Storage; the producer that prod/sbox read (see below). |
| `azure-pipelines-nvd-seed.yml` | DTSPO-32997 interim: one-off manual job to seed the DB from a local NVD cache (see below). |

The active jobs use `build-v10.gradle` and `db-migrations/v10`. `build-v6.gradle`
and `build-v9.gradle` are legacy and unused.

## One-off seed (DTSPO-32997 interim, no new infra)

When the shared DB has gone stale and the live-API update can't catch up (NVD
HTTP/2 instability + bulk re-modification of CVEs makes each "incremental" pull
behave like a full download), use `azure-pipelines-nvd-seed.yml` to get the DB
current without paging the live API:

1. The job builds a local NVD cache on the agent with
   [open-vulnerability-cli](https://github.com/jeremylong/open-vulnerability-cli)
   (`vulnz cve --cache --directory ./cache`). This is resumable — if the cache
   build is interrupted, re-run the job and completed year files are kept.
2. It then loads that cache into Postgres in one fast pass via DependencyCheck's
   datafeed support (`-Dnvd.api.datafeed.url=file:.../cache/nvdcve-{0}.json.gz`),
   so the DB load never touches the live NVD API.

Run it **manually**, `environment: sandbox` first to validate, then `prod`.
Requires Java 17 on the agent (vulnz 8.0.0+); the job uses `JAVA_HOME_17_X64` if
present, otherwise see the Docker alternative in the pipeline file. Once seeded,
the normal scheduled pipeline resumes small, fast incremental updates.

## NVD datafeed mirror (DTSPO-32997, Option B)

The live NVD API is unstable (HTTP/2 stream resets). Paging it directly makes the
DB update take many hours, frequently aborting or losing the agent, which in turn
leaves the shared cache stale and breaks downstream consumer builds.

`azure-pipelines-nvd-mirror.yml` mirrors the NVD CVE data with the
[open-vulnerability-cli](https://github.com/jeremylong/open-vulnerability-cli)
(`vulnz cve --cache --directory ./cache`) and publishes the gzipped yearly feed
files (`nvdcve-<year>.json.gz`, `nvdcve-modified.json.gz`, `cache.properties`) to
Azure Blob Storage. DependencyCheck then consumes the feed via
`-Dnvd.api.datafeed.url`, turning ~170 paged API calls into a handful of gz
downloads (hours -> minutes) and decoupling consumers from NVD outages — a failed
mirror run leaves the previously published copy in place.

### Realised setup

| Thing | Value |
| ----- | ----- |
| Subscription | `DTS-CFTPTL-INTSVC` |
| Resource group | `core-infra-intsvc-rg` (uksouth) |
| Storage account | `owaspnvdmirrorcftptl` (private, no public blob access) |
| Container | `nvd` |
| Datafeed URL | `https://owaspnvdmirrorcftptl.blob.core.windows.net/nvd/nvdcve-{0}.json.gz?<SAS>` |
| Read SAS | Key Vault secret `nvd-datafeed-sas`, container-scoped `rl`, 90-day expiry |

The container stays private. Consumers read it with a **rotated read SAS**: the
mirror mints a fresh 90-day container SAS on every run and stores it in Key Vault
as `nvd-datafeed-sas`, so the token is always renewed long before it expires (no
manual rotation, no silent 403s). Because prod reads `cftptl-intsvc` but sbox
reads `cftsbox-intsvc`, the mirror writes the same token to **both** vaults each
run (the blob itself lives only in the prod subscription; the SAS is just a URL
query string, so no cross-subscription RBAC is needed to consume it).

### How it runs

- **Schedule**: the mirror runs every 6h on the prod pool (`hmcts-cftptl-agent-pool`,
  3h cap), seeding from the existing blob copy and updating incrementally.
- **Full rebuild**: run the mirror manually with the `fullRebuild` parameter set
  to `true` to force a clean ~7h pull from NVD on the 9h sandbox pool
  (`hmcts-sandbox-agent-pool`) — e.g. if the blob mirror is ever lost or
  corrupted. The mirror is decoupled from consumers, so a long full run blocks
  nobody.
- **Cold-start note**: the initial blob contents were built off-agent (a local
  ~7h authenticated `vulnz` run) and uploaded once, because a from-scratch pull
  exceeds the prod pool's 3h cap. Routine runs only need the incremental path.

### Consumer wiring (already in place)

Both `azure-pipelines.yml` and `azure-pipelines-sbox.yml`:

- add `nvd-datafeed-sas` to the `AzureKeyVault@2` `secretsFilter`;
- set `nvdDatafeedUrl` to the blob base URL above;
- append `-Dnvd.api.datafeed.url=$(nvdDatafeedUrl)?$(nvd-datafeed-sas)` to the
  `Updating OWASP V15 DB` (`dependencyCheckUpdate`) options.

`-Dnvd.api.key` is kept only for the small recent "modified" window; the bulk
yearly data now comes from the blob mirror.

### RBAC the mirror needs

- `azurerm-prod` SP on `owaspnvdmirrorcftptl`: `Storage Blob Data Contributor`
  (upload/download with `--auth-mode login`) **and** the ability to list account
  keys (`Contributor` or *Storage Account Key Operator Service Role*), plus `set`
  on secrets in `cftptl-intsvc`.
- `azurerm-sandbox` SP: `set` on secrets in `cftsbox-intsvc` (already granted via
  the sbox pipelines).

### Downstream builds

Downstream consumers (e.g. `dependencyCheckAggregate` in the Jenkins pipeline
library) should set the same `nvd.api.datafeed.url` so they never fall back to the
live API when the shared cache is stale.
