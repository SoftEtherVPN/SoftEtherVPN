<script lang="ts">
	import { browser } from '$app/environment';
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc } from '$lib/rpc';
	import { createQuery } from '@tanstack/svelte-query';
	import Listener from './listener/listener.svelte';
	import Hub from './hub/hub.svelte';

	const serverName = browser ? location.host : '';

	const ddnsQuery = createQuery(() => ({
		queryKey: [dashboardKey, 'ddns'],
		queryFn: rpc.GetDDnsClientStatus
	}));
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
			<div class="card-body gap-3 p-4">
				<p class="font-semibold">{m.D_SM_SERVER__STATIC3()}</p>
				<div class="grid grid-cols-2 gap-2">
					<button class="btn justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_SSL()}
					</button>
					<button class="btn justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_FARM()}
					</button>
					<button class="btn justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_STATUS()}
					</button>
					<button class="btn btn-disabled justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_FARM_STATUS()}
					</button>
					<button class="btn justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_INFO()}
					</button>
					<button class="btn justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_CONNECTION()}
					</button>
					<button class="btn col-span-2 justify-start btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_SERVER__B_CONFIG()}
					</button>
				</div>
			</div>
		</div>
	</div>

	<!-- Bottom settings buttons -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<div class="card-body p-4">
			<div class="grid grid-cols-2 gap-2 *:btn *:btn-neutral *:not-dark:btn-soft sm:grid-cols-4">
				<button>{m.D_SM_SERVER__B_BRIDGE()}</button>
				<button>{m.D_SM_SERVER__B_L3()}</button>
				<a href="#/ipsec">{m.D_SM_SERVER__B_IPSEC()}</a>
				<button>{m.D_SM_SERVER__B_OPENVPN()}</button>
				<button>{m.D_SM_SERVER__B_DDNS()}</button>
				<button>{m.D_SM_SERVER__B_AZURE()}</button>
			</div>
		</div>
	</div>

	<!-- DDNS Footer -->
	<p class="text-sm opacity-70 max-sm:ml-4">
		{m.D_SM_SERVER__S_DDNS()}
		<span class="font-mono font-medium opacity-100">{ddnsQuery.data?.CurrentFqdn_str}</span>
	</p>
</div>
