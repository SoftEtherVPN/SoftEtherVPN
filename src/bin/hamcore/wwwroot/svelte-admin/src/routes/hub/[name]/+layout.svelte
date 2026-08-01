<script lang="ts">
	import { createQuery } from '@tanstack/svelte-query';
	import type { LayoutProps } from './$types';
	import { rpc, VpnRpcCreateHub } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import { m } from '$lib/paraglide/messages';
	import type { LocalizedString } from '$lib/paraglide/runtime';
	import type { LayoutRouteId } from './$types';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import type { LucideIcon } from '@lucide/svelte';
	import MenuIcon from '@lucide/svelte/icons/menu';
	import ServerIcon from '@lucide/svelte/icons/server';
	import UsersIcon from '@lucide/svelte/icons/users';
	import UsersRoundIcon from '@lucide/svelte/icons/users-round';
	import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';
	import SettingsIcon from '@lucide/svelte/icons/settings';
	import KeyRoundIcon from '@lucide/svelte/icons/key-round';
	import LinkIcon from '@lucide/svelte/icons/link';
	import FileCogIcon from '@lucide/svelte/icons/file-cog';
	import FilesIcon from '@lucide/svelte/icons/files';
	import FileBadgeIcon from '@lucide/svelte/icons/file-badge';
	import FileXIcon from '@lucide/svelte/icons/file-x';
	import NetworkIcon from '@lucide/svelte/icons/network';
	import ActivityIcon from '@lucide/svelte/icons/activity';

	let { params, children }: LayoutProps = $props();

	const hub = createQuery(() => ({
		queryKey: hubKeys.detail(params.name),
		queryFn: () => rpc.GetHub(new VpnRpcCreateHub({ HubName_str: params.name }))
	}));

	let drawerOpen = $state(false);
	const activeRoute = $derived(page.route.id);
	const closeDrawer = () => (drawerOpen = false);

	/**
	 * Direct children of `Base` within a route union: exactly one segment
	 * deeper, and with no parameters of their own so they stay resolvable from
	 * `params` alone. Adding `/hub/[name]/foo` makes it selectable in the menu;
	 * adding `/hub/[name]/foo/bar` or `/hub/[name]/[foo]` does not.
	 */
	type ChildRoute<
		Base extends string,
		Route extends string
	> = Route extends `${Base}/${infer Segment}`
		? Segment extends `${string}/${string}` | `${string}[${string}`
			? never
			: Route
		: never;

	type MenuItem = {
		title: LocalizedString;
		items: {
			route: ChildRoute<'/hub/[name]', LayoutRouteId>;
			content: LocalizedString;
			tooltip: LocalizedString;
			icon: LucideIcon;
		}[];
	}[];

	const menuItems: MenuItem = [
		{
			title: m.D_SM_HUB__STATIC1(),
			items: [
				{
					route: '/hub/[name]/users',
					icon: UsersIcon,
					content: m.D_SM_HUB__B_USER(),
					tooltip: m.D_SM_HUB__S_USER()
				},
				{
					route: '/hub/[name]/groups',
					icon: UsersRoundIcon,
					content: m.D_SM_HUB__B_GROUP(),
					tooltip: m.D_SM_HUB__S_GROUP()
				},
				{
					route: '/hub/[name]/access-lists',
					icon: ShieldCheckIcon,
					content: m.D_SM_HUB__B_ACCESS(),
					tooltip: m.D_SM_HUB__S_ACCESS()
				}
			]
		},
		{
			title: m.D_SM_HUB__STATIC2(),
			items: [
				{
					route: '/hub/[name]/properties',
					icon: SettingsIcon,
					content: m.D_SM_HUB__B_PROPERTY(),
					tooltip: m.D_SM_HUB__S_PROPERTY()
				},
				{
					route: '/hub/[name]/radius',
					icon: KeyRoundIcon,
					content: m.D_SM_HUB__B_RADIUS(),
					tooltip: m.D_SM_HUB__S_RADIUS()
				},
				{
					route: '/hub/[name]/cascade-connections',
					icon: LinkIcon,
					content: m.D_SM_HUB__B_LINK(),
					tooltip: m.D_SM_HUB__S_LINK()
				}
			]
		},
		{
			title: m.D_SM_HUB__STATIC4(),
			items: [
				{
					route: '/hub/[name]/log-setting',
					icon: FileCogIcon,
					content: m.D_SM_HUB__B_LOG(),
					tooltip: m.D_SM_HUB__S_LOG()
				},
				{
					route: '/hub/[name]/log-list',
					icon: FilesIcon,
					content: m.D_SM_HUB__B_LOG_FILE(),
					tooltip: m.D_SM_HUB__S_LOG()
				},
				{
					route: '/hub/[name]/trusted-ca',
					icon: FileBadgeIcon,
					content: m.D_SM_HUB__B_CA(),
					tooltip: m.D_SM_HUB__S_CA()
				},
				{
					route: '/hub/[name]/revoked-ca',
					icon: FileXIcon,
					content: m.D_SM_HUB__B_CRL(),
					tooltip: m.D_SM_HUB__S_CA()
				},
				{
					route: '/hub/[name]/secure-nat',
					icon: NetworkIcon,
					content: m.D_SM_HUB__B_SNAT(),
					tooltip: m.D_SM_HUB__S_SNAT()
				}
			]
		},
		{
			title: m.D_SM_HUB__STATIC5(),
			items: [
				{
					route: '/hub/[name]/sessions',
					icon: ActivityIcon,
					content: m.D_SM_HUB__B_SESSION(),
					tooltip: m.D_SM_HUB__B_SESSION()
				}
			]
		}
	];
</script>

{#if hub.isLoading}
	<div class="mt-6 h-[70vh] w-full skeleton"></div>
{:else}
	<div class="drawer mt-6 items-stretch lg:drawer-open">
		<input id="hub-drawer" type="checkbox" class="drawer-toggle" bind:checked={drawerOpen} />

		<div class="drawer-content lg:ps-4">
			<!-- Mobile: open-sidebar bar -->
			<div class="ms-2 mb-3 flex items-center gap-2 lg:hidden">
				<label
					for="hub-drawer"
					aria-label={m.D_SM_HUB__S_TITLE({ input0: params.name })}
					class="btn btn-square drawer-button btn-neutral btn-sm not-dark:btn-soft">
					<MenuIcon size={18} />
				</label>
				<span class="min-w-0 truncate font-semibold">
					{m.D_SM_HUB__S_TITLE({ input0: params.name })}
				</span>
			</div>

			<div class="h-full border border-base-300 bg-base-100">
				{@render children()}
			</div>
		</div>

		<div class="drawer-side h-auto">
			<label for="hub-drawer" aria-label="close sidebar" class="drawer-overlay h-screen"></label>
			<div class="border border-base-300 bg-base-100 lg:h-full">
				<!-- Hub identity -->
				<div class="flex items-center gap-3 border-b border-base-content/10 p-4">
					<span
						class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
						<ServerIcon size={18} />
					</span>
					<span class="min-w-0 truncate text-lg font-bold">{params.name}</span>
				</div>

				<ul class="menu w-full">
					{#each menuItems as menu}
						<li>
							<h2 class="menu-title">{menu.title}</h2>
							<ul>
								{#each menu.items as item}
									{@const Icon = item.icon}
									<li>
										<a
											class="tooltip tooltip-top tooltip-accent"
											class:menu-active={activeRoute?.includes(item.route)}
											href={resolve(item.route, params)}
											data-tip={item.tooltip}
											onclick={closeDrawer}>
											<Icon size={16} />
											{item.content}
										</a>
									</li>
								{/each}
							</ul>
						</li>
					{/each}
				</ul>
			</div>
		</div>
	</div>
{/if}
