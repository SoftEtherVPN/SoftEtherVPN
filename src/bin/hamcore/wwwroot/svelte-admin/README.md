# SoftEtherVPN — Svelte Admin UI

Web administration interface for [SoftEtherVPN](https://www.softether.org/), built with SvelteKit.

It talks to the VPN Server over its [JSON-RPC admin API](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients),
the same API the desktop Server Manager uses.

## Tech stack

| Tool                                                                                                  | Role                          |
| ----------------------------------------------------------------------------------------------------- | ----------------------------- |
| [SvelteKit](https://svelte.dev/docs/kit) (Svelte 5, runes)                                            | Framework, routing            |
| [Tailwind CSS v4](https://tailwindcss.com/) + [DaisyUI](https://daisyui.com/)                         | Styling and UI components     |
| [TanStack Query](https://tanstack.com/query)                                                          | Server state, caching         |
| [@vincjo/datatables](https://vincjo.fr/datatables)                                                    | Table sorting, search, paging |
| [Superforms](https://superforms.rocks/) + [Formsnap](https://formsnap.dev/) + [Zod](https://zod.dev/) | Forms and validation          |
| [Paraglide JS](https://inlang.com/m/gerre34r/library-inlang-paraglideJs)                              | Internationalization          |
| [Lucide](https://lucide.dev/)                                                                         | Icons                         |
| [Bun](https://bun.sh/)                                                                                | Runtime & package manager     |

## How it is served

The app is a **static single-page application**:

- `adapter-static` with a `200.html` fallback, so the whole app is a single `index.html`;
- **hash-based routing** (`#/hub/foo/users`), so the VPN Server's built-in HTTP handler needs
  no rewrite rules and no extra routes;
- **no server-side code** — there is no Node process at runtime, everything runs in the browser.

### Authentication

There is no login screen, and none is needed. The VPN Server serves the whole `/admin` tree
behind HTTP basic authentication (see `AdminWebProcGet` in `src/Cedar/Admin.c`), so the browser
prompts before the app even loads and then replays the `Authorization` header on every JSON-RPC
call. The RPC client is therefore created without credentials.

Per the server's 401 page, the username selects the scope:

- empty or `administrator` → entire VPN Server administrator;
- a Virtual Hub name → administrator of that hub only.

## Project layout

```
src/
├── lib/
│   ├── assets/
│   ├── components/
│   │   ├── ui/           # Generic primitives — no SoftEther knowledge
│   │   ├── policy-editor.svelte
│   │   ├── user-info.svelte
│   │   └── user-table.svelte
│   ├── paraglide/        # Generated from the .stb tables — do not edit
│   └── rpc/
│       ├── index.ts      # RPC client instance, re-exports the generated types
│       ├── query-keys.ts # TanStack Query key factory
│       ├── errors.ts     # RPC error code → localized message
│       ├── labels.ts     # RPC enum value → localized label
│       ├── policies.ts   # The `policy:*` field table (users and groups)
│       └── dates.ts      # SoftEther "never" date sentinel
└── routes/
    ├── +layout.svelte    # Query client, global error dialog, header
    ├── +page.svelte      # Dashboard
    ├── hub/              # Virtual Hub list, creation, and per-hub management
    ├── listener/         # Listener management
    ├── ipsec/            # IPsec / L2TP settings
    ├── openvpn/          # OpenVPN / MS-SSTP settings
    └── azure-settings/   # VPN Azure settings
```

Anything under `src/lib/components/ui/` must stay free of SoftEther knowledge — a component
that imports `$lib/rpc` belongs one level up.

## Dependencies on the rest of the repository

Two, both behind aliases declared in `svelte.config.js`, so moving this project only means
updating those two lines:

| Alias      | Points to                                               | Used for                  |
| ---------- | ------------------------------------------------------- | ------------------------- |
| `$vpnrpc`  | `developer_tools/vpnserver-jsonrpc-clients/…/vpnrpc.ts` | Generated JSON-RPC client |
| `$pencore` | `src/PenCore/`                                          | Icons and bitmaps         |

There is a third, implicit one: `vite.config.ts` runs `convert-stb.ts` on every build, which
parses `src/bin/hamcore/strtable_*.stb` and writes `messages/<locale>.json`. Translations are
therefore **never written by hand** — they are the same strings the Server Manager uses.
Locales currently produced: `en`, `id`, `ja`, `ko`, `pt_br`, `ru`, `tr`, `tw`, `cn`.

## Prerequisites

- [Bun](https://bun.sh/) ≥ 1.0 (or Node.js with npm)
- A running SoftEtherVPN server, for the API

## Getting started

```sh
bun install

# RPC_SERVER_URL must point to the SoftEtherVPN server
RPC_SERVER_URL=http://localhost:5555 bun run dev
```

The Vite dev proxy forwards `/api` requests to `RPC_SERVER_URL`. You can store the variable in
`.env.development.local` to avoid repeating it:

```sh
# .env.development.local
RPC_SERVER_URL=http://localhost:5555
```

That file is gitignored and only loaded in development.

## Scripts

| Command           | What it does                         |
| ----------------- | ------------------------------------ |
| `bun run dev`     | Dev server with the `/api` proxy     |
| `bun run build`   | Production build into `build/`       |
| `bun run preview` | Serve the production build locally   |
| `bun run check`   | `svelte-check` (TypeScript + Svelte) |
| `bun run lint`    | Prettier, check only                 |
| `bun run format`  | Prettier, write                      |

`npm` works everywhere `bun` is shown.

## Notes for contributors

- **Query keys** always come from `$lib/rpc/query-keys`, never inline. Invalidation matches on
  prefix, and that only works if the whole app agrees on the key tree.
- **Lists** use `$lib/components/ui/data-table.svelte`. Declare columns, not markup: a column
  with a plain `value` needs no snippet and is sortable for free.
- **Strings** come from `$lib/paraglide/messages`, whose keys are the `.stb` names. Editing
  `messages/*.json` by hand is pointless — `convert-stb.ts` overwrites them.
