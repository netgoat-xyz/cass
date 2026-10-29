<img width="2968" height="841" alt="NetGoat" src="assets/netgoat-banner.png" />

# NetGoat CAS API

The Central Administrative Service (CAS) API. It is the administrative JSON
backend behind the [CAS admin panel](https://github.com/netgoat-xyz/cass-admin):
instances, cluster join material, UI-managed configuration, deployment records
and an audit trail.

CAS is deliberately small. It does **not** proxy traffic, talk to agents over a
control channel, or serve a dashboard. Deployment requests are recorded as
`queued`; execution is not implemented.

## Architecture

```text
cass-admin (Next.js, :3200)
        │  server-side /api/cas proxy
        ▼
cass (Go, :8088)  ──►  CAS_STATE_FILE (JSON on disk)
```

State is a single JSON document guarded by an in-process mutex. There is no
database and no external queue, so a single replica is the supported topology.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Readiness and service identity (public) |
| `GET` | `/api/overview` | Dashboard counts |
| `GET` | `/api/instances` | List registered instances |
| `POST` | `/api/instances` | Register an instance |
| `GET` | `/api/instances/:id` | View an instance |
| `PATCH` | `/api/instances/:id` | Edit an instance |
| `POST` | `/api/join` | Complete an instance join |
| `GET` | `/api/config` | Read UI-managed configuration |
| `PUT` | `/api/config` | Replace UI-managed configuration |
| `GET` | `/api/deployments` | List deployment records |
| `POST` | `/api/deployments` | Queue a deployment record |
| `GET` | `/api/audit` | Read CAS audit entries |

Everything under `/api/` requires `Authorization: Bearer $CAS_API_KEY` when the
key is set. `/health` is always public.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Go 1.24 (stdlib only, no third-party modules) |
| Storage | JSON file at `CAS_STATE_FILE` |
| Container | distroless static, non-root |

There are no external Go dependencies, so `go.sum` is intentionally absent.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CAS_ADDR` | `:8088` | Listen address |
| `CAS_API_KEY` | empty | Bearer key required on `/api/*`; empty disables auth |
| `CAS_STATE_FILE` | `./data/cas.json` | Persisted state path |
| `CAS_PUBLIC_URL` | `http://localhost:8088` | Public origin shown in join material |

Copy [`.env.example`](.env.example) to `.env` for local runs. Never commit
`.env`. Setting no `CAS_API_KEY` is only acceptable on loopback.

## Build and test

```bash
go vet ./...
go test -race ./...
gofmt -l .          # must print nothing
go build -o cas-api .
./cas-api
```

## Docker

```bash
docker build -t netgoat-cass .
docker run --rm -p 8088:8088 \
  -e CAS_API_KEY="$(openssl rand -hex 32)" \
  -v cass-data:/app/data \
  netgoat-cass
```

Published images: `ghcr.io/netgoat-xyz/cass`. The runtime is
`gcr.io/distroless/static-debian12:nonroot` and the container runs as
`nonroot`. The healthcheck uses a static busybox `wget` against `/health`.

## Deployment

Mount a persistent volume at `/app/data` so state survives restarts. Terminate
TLS at a reverse proxy; CAS speaks plain HTTP. Set `CAS_API_KEY` to a long
random value and keep the admin panel's proxy as the only client. The panel
holds the key server-side and never exposes it to the browser.

## Security

- Constant-time comparison for the bearer key.
- Join tokens are one-time and stored hashed; the agent key is returned once.
- No third-party dependencies, so the supply-chain surface is the Go stdlib
  and the base image.
- Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU Affero General Public License v3.0](LICENSE).
