# Contributing to deskOTP

Thank you for considering a contribution to deskOTP. This is a solo-maintainer project and contributions are welcome — whether that is a bug fix, a new import format, a translation, or documentation improvement.

## Prerequisites

- **Go 1.23+** — https://go.dev/dl/
- **Node.js 20+** — https://nodejs.org/ or via [fnm](https://fnm.vercel.app/)
- **Wails CLI** — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **System libraries (Linux)**:
  - Ubuntu/Debian: `sudo apt-get install libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config build-essential`
  - Fedora/RHEL: `sudo dnf install gtk3-devel webkit2gtk4.1-devel`
  - Arch: `sudo pacman -S gtk3 webkit2gtk-4.1`

## Getting Started

```bash
git clone https://github.com/extricator/deskOTP.git
cd deskOTP
cd frontend && npm install && cd ..
wails dev
```

`wails dev` starts a hot-reloading development server. The frontend is served at http://localhost:34115.

## Building

```bash
wails build
```

Output binary: `./build/bin/deskOTP`. The `webkit2_41` build tag is applied automatically via `wails.json`.

## Code Style

**Go:**

```bash
go fmt ./...
go vet ./...
go test ./...
```

**TypeScript/Frontend:**

```bash
cd frontend
npm run lint
npm run format:check
npm run typecheck
```

ESLint and Prettier configs are in `frontend/`. The pre-commit hook runs lint-staged automatically on staged files.

## Commit Messages

Conventional Commits is encouraged but not enforced:

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation
- `refactor:` — code restructuring
- `test:` — test changes

A one-line summary is sufficient for small changes. Include a body when context helps future readers.

## Pull Requests

- For large changes, open an issue first to discuss the approach.
- PRs should pass `go vet`, `go test ./...`, and `npm run lint` before review.
- Describe what the PR does and why in the PR description.
- Keep the scope focused — one concern per PR makes review easier.

## Translations

See [TRANSLATING.md](TRANSLATING.md) for how to add a new language.
