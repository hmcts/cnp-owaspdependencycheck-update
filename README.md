# cnp-owaspdependencycheck-update

Pipeline for automating owasp dependency check updates to Azure DB.

## Pipelines

| File | Purpose |
| ---- | ------- |
| `azure-pipelines.yml` | Production: Flyway-migrates the shared cached OWASP DB then refreshes the NVD data (every 3h). |
| `azure-pipelines-sbox.yml` | Sandbox equivalent of the production pipeline. |
| `azure-pipelines-nvd-mirror.yml` | DTSPO-32997 Option B: mirrors the NVD datafeed to Blob Storage (see below). |
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

### Rollout steps

1. **Provision storage**: a storage account + blob container (e.g. `<account>/nvd`)
   reachable by the prod agent pool and the downstream Jenkins builds. Give the
   `azurerm-prod` service-connection principal `Storage Blob Data Contributor`.
2. **Consumer read access**: enable anonymous read on the container, or generate a
   long-lived read SAS to append to the datafeed URL.
3. **Configure the mirror pipeline**: set `storageAccount` (and `vulnzVersion` if
   newer) in `azure-pipelines-nvd-mirror.yml`. Ensure the agent has Java 17+
   (vulnz 8.0.0+ requirement) or use the Docker alternative noted in the file.
4. **Run the mirror** and confirm `cache.properties` + `nvdcve-*.json.gz` land in
   the container.
5. **Wire up consumers**: set `nvdDatafeedUrl` to
   `https://<account>.blob.core.windows.net/nvd/nvdcve-{0}.json.gz` and append
   `-Dnvd.api.datafeed.url=$(nvdDatafeedUrl)` to the `Updating OWASP V15 DB`
   options — **on sandbox first**, then production once validated.
6. **Downstream builds** (e.g. `dependencyCheckAggregate` in the Jenkins pipeline
   library) should set the same `nvd.api.datafeed.url` so they never fall back to
   the live API when the shared cache is stale.
