# SoftEtherVPN — Svelte Admin UI

Web administration interface for [SoftEtherVPN](https://www.softether.org/), built with SvelteKit.

## Tech stack

| Tool                                                                          | Role                           |
| ----------------------------------------------------------------------------- | ------------------------------ |
| [SvelteKit](https://kit.svelte.dev/)                                          | Main framework                 |
| [Tailwind CSS v4](https://tailwindcss.com/)                                   | Styling                        |
| [shadcn-svelte](https://shadcn-svelte.com/) + [bits-ui](https://bits-ui.com/) | UI components                  |
| [TanStack Query](https://tanstack.com/query)                                  | Async data fetching            |
| [Paraglide JS](https://inlang.com/m/gerre34r/library-inlang-paraglideJs)      | Internationalization (EN / FR) |
| [Bun](https://bun.sh/)                                                        | Runtime & package manager      |

## Architecture

```
src/
├── lib/
│   ├── components/ui/   # Reusable UI components
│   └── paraglide/       # Auto-generated i18n files
└── routes/
    ├── hub/             # VPN Hub status and configuration
    ├── listerner/       # Listener management (create, delete, stop)
    ├── +page.svelte     # Main page
    └── +layout.svelte   # Global layout
```

## Prerequisites

- [Bun](https://bun.sh/) ≥ 1.0
- A running SoftEtherVPN server (for the API)

## Getting started

```sh
# Install dependencies
bun install
# or
npm install

# Start the development server
# RPC_SERVER_URL must point to the SoftEtherVPN server
RPC_SERVER_URL=http://localhost:5555 bun run dev
# or
RPC_SERVER_URL=http://localhost:5555 npm run dev
```

The Vite proxy automatically forwards `/api` requests to `RPC_SERVER_URL`.

You can also store this variable in a `.env.development.local` file to avoid setting it every time:

```sh
# .env.development.local
RPC_SERVER_URL=http://localhost:5555
```

This file is gitignored by default and only loaded in development.

## Production build

```sh
bun run build && bun run preview
# or
npm run build && npm run preview
```
