<script lang="ts">
	import { browser } from '$app/environment';
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc } from '$lib/rpc';
	import { createQuery } from '@tanstack/svelte-query';
	import Listener from './listener/listener.svelte';
	import Hub from './hub/hub.svelte';
	import ServerStatus from './server-status.svelte';

	const serverName = browser ? location.host : '';

	const ddnsQuery = createQuery(() => ({
		queryKey: [dashboardKey, 'ddns'],
		queryFn: rpc.GetDDnsClientStatus
	}));

	let serverStatusOpen = $state(false);
</script>

<div class="mt-6 flex flex-col gap-4">
	<!-- Title -->
	<h1 class="text-2xl font-bold max-sm:ml-4">
		{m.D_SM_SERVER__CAPTION({ input0: serverName })}
	</h1>

	<Hub />

	<!-- Middle: Listeners + Server Settings -->
	<div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
		<Listener />

		<!-- VPN Server and Network Information and Settings -->
		<div class="card bg-base-100 shadow dark:bg-base-300">
			<div class="card-body">
				<h3 class="card-title">{m.D_SM_SERVER__STATIC3()}</h3>
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
					<button>
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
		<div class="card-body">
			<div class="grid grid-cols-2 gap-2 *:btn *:btn-neutral *:not-dark:btn-soft sm:grid-cols-4">
				<button>{m.D_SM_SERVER__B_BRIDGE()}</button>
				<button>{m.D_SM_SERVER__B_L3()}</button>
				<a href="#/ipsec">{m.D_SM_SERVER__B_IPSEC()}</a>
				<a href="#/openvpn">{m.D_SM_SERVER__B_OPENVPN()}</a>
				<button>{m.D_SM_SERVER__B_DDNS()}</button>
				<a href="#/azure-settings" >{m.D_SM_SERVER__B_AZURE()}</a>
			</div>
		</div>
	</div>

	<!-- DDNS Footer -->
	<p class="text-sm opacity-70 max-sm:ml-4">
		{m.D_SM_SERVER__S_DDNS()}
		<span class="font-mono font-medium opacity-100">{ddnsQuery.data?.CurrentFqdn_str}</span>
	</p>
</div>

<ServerStatus bind:open={serverStatusOpen} />
