<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc } from '$lib/rpc';
	import { translateHubOnline, translateHubType } from '$lib/translation';
	import { createQuery } from '@tanstack/svelte-query';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';

	const locale = getLocale();
	const query = createQuery(() => ({
		queryKey: [dashboardKey, 'hub'],
		queryFn: async () => (await rpc.EnumHub()).HubList,
		initialData: []
	}));
</script>

<!-- Virtual Hub Table -->
<div class="card bg-base-100 shadow dark:bg-base-300">
	<div class="card-body gap-4 p-4">
		<div class="h-56 overflow-x-auto">
			<table class="table w-max">
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
						<th>{m.SM_HUB_COLUMN_9()}</th>
						<th>{m.SM_HUB_COLUMN_10()}</th>
						<th>{m.SM_HUB_COLUMN_11()}</th>
						<th>{m.SM_SESS_COLUMN_6()}</th>
						<th>{m.SM_SESS_COLUMN_7()}</th>
					</tr>
				</thead>
				<tbody>
					{#each query.data as hub (hub.HubName_str)}
						{@const transferBytes =
							hub['Ex.Recv.BroadcastBytes_u64'] +
							hub['Ex.Recv.UnicastBytes_u64'] +
							hub['Ex.Send.BroadcastBytes_u64'] +
							hub['Ex.Send.UnicastBytes_u64']}
						{@const transferPackets =
							hub['Ex.Recv.BroadcastCount_u64'] +
							hub['Ex.Recv.UnicastCount_u64'] +
							hub['Ex.Send.BroadcastCount_u64'] +
							hub['Ex.Send.UnicastCount_u64']}
						<tr>
							<td class="font-medium">{hub.HubName_str}</td>
							<td>
								<span
									class="badge badge-sm"
									class:badge-success={hub.Online_bool}
									class:badge-error={!hub.Online_bool}>
									{translateHubOnline(hub.Online_bool)}
								</span>
							</td>
							<td>{translateHubType(hub.HubType_u32)}</td>
							<td>{hub.NumUsers_u32}</td>
							<td>{hub.NumGroups_u32}</td>
							<td>{hub.NumSessions_u32}</td>
							<td>{hub.NumMacTables_u32}</td>
							<td>{hub.NumIpTables_u32}</td>
							<td>{hub.NumLogin_u32}</td>
							<td>
								{datetime(locale, hub.LastLoginTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</td>
							<td>
								{datetime(locale, hub.LastCommTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</td>
							<td>{number(locale, transferBytes)}</td>
							<td>{number(locale, transferPackets)}</td>
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
