<script lang="ts">
	import { browser } from '$app/environment';
	import { m } from '$lib/paraglide/messages';
	import { number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcServerStatus } from '$lib/rpc';
	import { translateHubType } from '$lib/translation';
	import { createQuery } from '@tanstack/svelte-query';
	import Listener from './listener/listener.svelte';
	import Hub from './hub/hub.svelte';
	import ServerStatus from './server-status.svelte';
	import TcpConnections from './tcp-connections.svelte';
	import ServerIcon from '@lucide/svelte/icons/server';
	import GlobeIcon from '@lucide/svelte/icons/globe';
	import LayersIcon from '@lucide/svelte/icons/layers';
	import ActivityIcon from '@lucide/svelte/icons/activity';
	import UsersIcon from '@lucide/svelte/icons/users';
	import PlugZapIcon from '@lucide/svelte/icons/plug-zap';
	import SettingsIcon from '@lucide/svelte/icons/settings';

	const locale = getLocale();
	const serverName = browser ? location.host : '';

	const ddnsQuery = createQuery(() => ({
		queryKey: [dashboardKey, 'ddns'],
		queryFn: rpc.GetDDnsClientStatus
	}));

	// Fleet-wide status. Shares its cache with the Server Status dialog.
	const statusQuery = createQuery(() => ({
		queryKey: [dashboardKey, 'status'],
		queryFn: rpc.GetServerStatus,
		initialData: new VpnRpcServerStatus(),
		refetchInterval: 5000
	}));

	let serverStatusOpen = $state(false);
	let tcpConnectionOpen = $state(false);

	let metrics = $derived([
		{
			label: m.SM_ST_NUM_HUB_TOTAL(),
			value: statusQuery.data.NumHubTotal_u32,
			icon: LayersIcon
		},
		{
			label: m.SM_ST_NUM_SESSION_TOTAL(),
			value: statusQuery.data.NumSessionsTotal_u32,
			icon: ActivityIcon
		},
		{
			label: m.SM_ST_NUM_USERS(),
			value: statusQuery.data.NumUsers_u32,
			icon: UsersIcon
		},
		{
			label: m.SM_ST_NUM_TCP(),
			value: Math.max(statusQuery.data.NumTcpConnections_u32 - 1, 0),
			icon: PlugZapIcon
		}
	]);
</script>

<div class="mt-6 flex flex-col gap-4">
	<!-- Command header: server identity, live status and DDNS endpoint -->
	<div class="card border border-base-300 bg-base-200 dark:border-base-100">
		<div class="card-body gap-4 p-4 sm:p-6">
			<div class="flex flex-wrap items-start justify-between gap-4">
				<div class="flex items-start gap-3">
					<span
						class="grid size-11 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
						<ServerIcon size={22} />
					</span>
					<div class="flex flex-col gap-1">
						<h1 class="text-2xl leading-tight font-bold">
							{m.D_SM_SERVER__CAPTION({ input0: serverName })}
						</h1>
						<p class="flex items-center gap-1.5 text-sm opacity-70">
							<GlobeIcon size={14} class="shrink-0" />
							<span>{m.D_SM_SERVER__S_DDNS()}</span>
							<span
								class="tooltip font-mono font-medium opacity-100"
								data-tip={ddnsQuery.data?.CurrentFqdn_str ?? ''}>
								{ddnsQuery.data?.CurrentFqdn_str ?? '—'}
							</span>
						</p>
					</div>
				</div>

				<!-- Live server status pill -->
				<div class="flex items-center gap-2 rounded-box bg-base-100 px-3 py-2 dark:bg-base-300">
					<span class="inline-grid *:[grid-area:1/1]">
						<span class="status status-success animate-ping"></span>
						<span class="status status-success"></span>
					</span>
					<div class="flex flex-col items-start gap-0.5 leading-tight">
						<span class="text-xs opacity-60">{m.SM_SERVER_STATUS()}</span>
						<span class="badge badge-sm badge-success badge-soft">
							{translateHubType(statusQuery.data.ServerType_u32)}
						</span>
					</div>
				</div>
			</div>

			<!-- Live metric band -->
			<div class="stats stats-vertical w-full bg-base-100 sm:stats-horizontal dark:bg-base-300">
				{#each metrics as metric (metric.label)}
					<div class="stat gap-1 px-4 py-3">
						<div class="stat-figure text-primary opacity-80">
							<metric.icon size={26} />
						</div>
						<div class="stat-title text-xs">{metric.label}</div>
						<div class="stat-value text-2xl tabular-nums">{number(locale, metric.value)}</div>
					</div>
				{/each}
			</div>
		</div>
	</div>

	<Hub />

	<!-- Middle: Listeners + Server Settings -->
	<div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
		<Listener />

		<!-- VPN Server and Network Information and Settings -->
		<div class="card bg-base-100 shadow dark:bg-base-300">
			<div class="card-body gap-4">
				<h3 class="flex items-center gap-2 card-title">
					<SettingsIcon size={18} class="opacity-70" />
					{m.D_SM_SERVER__STATIC3()}
				</h3>
				<div class="grid grid-cols-2 gap-2 *:btn *:justify-start *:btn-neutral *:not-dark:btn-soft">
					<button>
						{m.D_SM_SERVER__B_SSL()}
					</button>
					<button>
						{m.D_SM_SERVER__B_FARM()}
					</button>
					<button onclick={() => (serverStatusOpen = true)}>
						{m.D_SM_SERVER__B_STATUS()}
					</button>
					<button>
						{m.D_SM_SERVER__B_FARM_STATUS()}
					</button>
					<button>
						{m.D_SM_SERVER__B_INFO()}
					</button>
					<button onclick={() => (tcpConnectionOpen = true)}>
						{m.D_SM_SERVER__B_CONNECTION()}
					</button>
					<button>
						{m.D_SM_SERVER__B_CONFIG()}
					</button>
				</div>
			</div>
		</div>
	</div>

	<!-- Bottom settings buttons -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<div class="card-body gap-4">
			<div class="grid grid-cols-2 gap-2 *:btn *:btn-neutral *:not-dark:btn-soft sm:grid-cols-4">
				<button>{m.D_SM_SERVER__B_BRIDGE()}</button>
				<button>{m.D_SM_SERVER__B_L3()}</button>
				<a href="#/ipsec">{m.D_SM_SERVER__B_IPSEC()}</a>
				<a href="#/openvpn">{m.D_SM_SERVER__B_OPENVPN()}</a>
				<button>{m.D_SM_SERVER__B_DDNS()}</button>
				<a href="#/azure-settings">{m.D_SM_SERVER__B_AZURE()}</a>
			</div>
		</div>
	</div>
</div>

<ServerStatus bind:open={serverStatusOpen} />
<TcpConnections bind:open={tcpConnectionOpen} />
