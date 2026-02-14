<script lang="ts">
	import { Dialog, DialogContent, DialogTitle } from '$lib/components/ui/dialog';
	import DialogHeader from '$lib/components/ui/dialog/dialog-header.svelte';
	import { Table, TableBody, TableHeader, TableRow } from '$lib/components/ui/table';
	import TableCell from '$lib/components/ui/table/table-cell.svelte';
	import TableHead from '$lib/components/ui/table/table-head.svelte';
	import { m } from '$lib/paraglide/messages';
	import { datetime, number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { rpc, VpnRpcHubStatus } from '$lib/rpc';
	import { translateHubOnline, translateHubType, translateSecureNat } from '$lib/utils/translation';
	import { createQuery } from '@tanstack/svelte-query';

	interface Props {
		open: boolean;
		hub?: string;
	}

	let { open = $bindable(), hub }: Props = $props();

	const query = createQuery(() => ({
		queryKey: ['hub', hub, 'propeties'],
		get enabled() {
			return hub != null && open;
		},
		queryFn: () => rpc.GetHubStatus(new VpnRpcHubStatus({ HubName_str: hub })),
		refetchInterval: 5000
	}));

	const locale = getLocale();
</script>

<Dialog bind:open>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>{m.SM_HUB_STATUS_CAPTION({ input0: hub! })}</DialogTitle>
		</DialogHeader>
		<div class="h-[50vh] overflow-y-auto">
			{#if query.data != null}
				<Table class="">
					<TableHeader>
						<TableRow>
							<TableHead>{m.SM_STATUS_COLUMN_1()}</TableHead>
							<TableHead>{m.SM_STATUS_COLUMN_2()}</TableHead>
						</TableRow>
					</TableHeader>
					<TableBody class="">
						<TableRow>
							<TableCell>{m.SM_HUB_STATUS_HUBNAME()}</TableCell>
							<TableCell>{query.data.HubName_str}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_STATUS_ONLINE()}</TableCell>
							<TableCell>{translateHubOnline(query.data.Online_bool)}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_TYPE()}</TableCell>
							<TableCell>{translateHubType(query.data.HubType_u32)}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_SECURE_NAT()}</TableCell>
							<TableCell>{translateSecureNat(query.data.SecureNATEnabled_bool)}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_SESSIONS()}</TableCell>
							<TableCell>{query.data.NumSessions_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_ACCESSES()}</TableCell>
							<TableCell>{query.data.NumAccessLists_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_USERS()}</TableCell>
							<TableCell>{query.data.NumUsers_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_GROUPS()}</TableCell>
							<TableCell>{query.data.NumGroups_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_MAC_TABLES()}</TableCell>
							<TableCell>{query.data.NumMacTables_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_IP_TABLES()}</TableCell>
							<TableCell>{query.data.NumIpTables_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_NUM_LOGIN()}</TableCell>
							<TableCell>{query.data.NumLogin_u32}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_LAST_LOGIN_TIME()}</TableCell>
							<TableCell>
								{datetime(locale, query.data.LastLoginTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_LAST_COMM_TIME()}</TableCell>
							<TableCell>
								{datetime(locale, query.data.LastCommTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_HUB_CREATED_TIME()}</TableCell>
							<TableCell>
								{datetime(locale, query.data.CreatedTime_dt, {
									dateStyle: 'medium',
									timeStyle: 'medium'
								})}
							</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_SEND_UCAST_NUM()}</TableCell>
							<TableCell>{number(locale, query.data['Send.UnicastCount_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_SEND_UCAST_SIZE()}</TableCell>
							<TableCell>{number(locale, query.data['Send.UnicastBytes_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_SEND_BCAST_NUM()}</TableCell>
							<TableCell>{number(locale, query.data['Send.BroadcastCount_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_SEND_BCAST_SIZE()}</TableCell>
							<TableCell>{number(locale, query.data['Send.BroadcastBytes_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_RECV_UCAST_NUM()}</TableCell>
							<TableCell>{number(locale, query.data['Recv.UnicastCount_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_RECV_UCAST_SIZE()}</TableCell>
							<TableCell>{number(locale, query.data['Recv.UnicastBytes_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_RECV_BCAST_NUM()}</TableCell>
							<TableCell>{number(locale, query.data['Recv.BroadcastCount_u64'])}</TableCell>
						</TableRow>
						<TableRow>
							<TableCell>{m.SM_ST_RECV_BCAST_SIZE()}</TableCell>
							<TableCell>{number(locale, query.data['Recv.BroadcastBytes_u64'])}</TableCell>
						</TableRow>
					</TableBody>
				</Table>
			{/if}
		</div>
	</DialogContent>
</Dialog>
