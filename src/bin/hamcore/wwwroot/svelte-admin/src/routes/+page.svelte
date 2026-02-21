<script lang="ts">
	import { browser } from '$app/environment';
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc } from '$lib/rpc';
	import { createQuery } from '@tanstack/svelte-query';
	import Listener from './listener/listener.svelte';

	const serverName = browser ? location.host : '';

	const hubs = [
		{
			name: 'VPN',
			online: true,
			type: 'standalone',
			users: 1,
			groups: 0,
			sessions: 1,
			mac: 12,
			ip: 16
		}
	];

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

	<!-- Virtual Hub Table -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<div class="card-body gap-4 p-4">
			<div class="h-56 overflow-x-auto">
				<table class="table">
					<thead>
						<tr>
							<th>{m.SM_HUB_COLUMN_1()}</th>
							<th>{m.SM_HUB_COLUMN_2()}</th>
							<th>{m.SM_HUB_COLUMN_3()}</th>
							<th>{m.SM_HUB_COLUMN_4()}</th>
							<th>{m.SM_HUB_COLUMN_5()}</th>
							<th>{m.SM_HUB_COLUMN_6()}</th>
							<th>{m.SM_HUB_COLUMN_7()}</th>
							<th>{m.SM_HUB_COLUMN_8()}</th>
						</tr>
					</thead>
					<tbody>
						{#each hubs as hub}
							<tr>
								<td class="font-medium">{hub.name}</td>
								<td>
									{#if hub.online}
										<span class="badge badge-sm badge-success">{m.SM_HUB_ONLINE()}</span>
									{:else}
										<span class="badge badge-sm badge-error">{m.SM_HUB_OFFLINE()}</span>
									{/if}
								</td>
								<td>{m.SM_HUB_STANDALONE()}</td>
								<td>{hub.users}</td>
								<td>{hub.groups}</td>
								<td>{hub.sessions}</td>
								<td>{hub.mac}</td>
								<td>{hub.ip}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<!-- Hub action buttons -->
			<div class="flex flex-wrap gap-2">
				<button class="btn btn-sm btn-primary">{m.D_SM_SERVER__IDOK()}</button>
				<button class="btn btn-sm btn-success">{m.D_SM_SERVER__B_ONLINE()}</button>
				<button class="btn btn-sm btn-warning">{m.D_SM_SERVER__B_OFFLINE()}</button>
				<button class="btn btn-sm btn-neutral not-dark:btn-soft">
					{m.D_SM_SERVER__B_HUB_STATUS()}
				</button>
				<button class="btn btn-sm btn-neutral not-dark:btn-soft">
					{m.D_SM_SERVER__B_CREATE()}
				</button>
				<button class="btn btn-sm btn-neutral not-dark:btn-soft">{m.D_SM_SERVER__B_EDIT()}</button>
				<button class="btn btn-sm btn-error">{m.D_SM_SERVER__B_DELETE()}</button>
			</div>
		</div>
	</div>

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
				<button>{m.D_SM_SERVER__B_IPSEC()}</button>
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
