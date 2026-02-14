<script lang="ts">
	import { Card, CardContent, CardFooter } from '$lib/components/ui/card';
	import { createSvelteTable, FlexRender } from '$lib/components/ui/data-table';
	import {
		Table,
		TableBody,
		TableCell,
		TableHead,
		TableHeader,
		TableRow
	} from '$lib/components/ui/table';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnRpcEnumHubItem } from '$lib/rpc';
	import { createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { getCoreRowModel, type ColumnDef, type RowSelectionState } from '@tanstack/table-core';
	import { number, datetime } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { Button } from '$lib/components/ui/button';
	import Status from './status.svelte';
	import { translateHubOnline, translateHubType } from '$lib/utils/translation';

	let locale = getLocale();

	const columns: ColumnDef<VpnRpcEnumHubItem>[] = [
		{ accessorKey: 'HubName_str', header: m.SM_HUB_COLUMN_1() },
		{
			accessorFn: (r) => translateHubOnline(r.Online_bool),
			header: m.SM_HUB_COLUMN_2()
		},
		{
			accessorFn: (r) => translateHubType(r.HubType_u32),
			header: m.SM_HUB_COLUMN_3()
		},
		{ accessorKey: 'NumUsers_u32', header: m.SM_HUB_COLUMN_4() },
		{ accessorKey: 'NumGroups_u32', header: m.SM_HUB_COLUMN_5() },
		{ accessorKey: 'NumSessions_u32', header: m.SM_HUB_COLUMN_6() },
		{ accessorKey: 'NumMacTables_u32', header: m.SM_HUB_COLUMN_7() },
		{ accessorKey: 'NumIpTables_u32', header: m.SM_HUB_COLUMN_8() },
		{ accessorKey: 'NumLogin_u32', header: m.SM_HUB_COLUMN_9() },
		{
			accessorKey: 'LastLoginTime_dt',
			header: m.SM_HUB_COLUMN_10(),
			cell: (c) => datetime(locale, c.getValue(), { dateStyle: 'medium', timeStyle: 'medium' })
		},
		{
			accessorKey: 'LastCommTime_dt',
			header: m.SM_HUB_COLUMN_11(),
			cell: (c) => datetime(locale, c.getValue(), { dateStyle: 'medium', timeStyle: 'medium' })
		},
		{
			accessorFn: (r) => {
				let value =
					r['Ex.Recv.BroadcastBytes_u64'] +
					r['Ex.Recv.UnicastBytes_u64'] +
					r['Ex.Send.BroadcastBytes_u64'] +
					r['Ex.Send.UnicastBytes_u64'];
				return number(locale, value);
			},
			header: m.SM_SESS_COLUMN_6()
		},
		{
			accessorFn: (r) => {
				let value =
					r['Ex.Recv.BroadcastCount_u64'] +
					r['Ex.Recv.UnicastCount_u64'] +
					r['Ex.Send.BroadcastCount_u64'] +
					r['Ex.Send.UnicastCount_u64'];
				return number(locale, value);
			},
			header: m.SM_SESS_COLUMN_7()
		}
	];

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: ['hub'],
		queryFn: async () => {
			let r = await rpc.EnumHub();
			return r.HubList;
		},
		refetchInterval: 5000,
		initialData: []
	}));

	let rowSelection = $state<RowSelectionState>({});
	const table = createSvelteTable({
		get data() {
			return query.data;
		},
		getRowId: (r) => r.HubName_str,
		columns,
		getCoreRowModel: getCoreRowModel(),
		enableRowSelection: true,
		enableMultiRowSelection: false,
		onRowSelectionChange: (u) => {
			if (typeof u === 'function') rowSelection = u(rowSelection);
			else rowSelection = u;
		},
		state: {
			get rowSelection() {
				return rowSelection;
			}
		}
	});

	let rowSelected = $derived.by(() =>
		query.data.find((r) => rowSelection[r.HubName_str.toString()])
	);
	let isSelected = $derived(rowSelected != null);

	let statusOpen = $state(false);
</script>

<Card>
	<CardContent>
		<div class="h-48">
			<Table>
				<TableHeader>
					{#each table.getHeaderGroups() as headerGroup (headerGroup.id)}
						<TableRow>
							{#each headerGroup.headers as header (header.id)}
								<TableHead colspan={header.colSpan}>
									{#if !header.isPlaceholder}
										<FlexRender
											content={header.column.columnDef.header}
											context={header.getContext()} />
									{/if}
								</TableHead>
							{/each}
						</TableRow>
					{/each}
				</TableHeader>
				<TableBody>
					{#each table.getRowModel().rows as row (row.id)}
						<TableRow
							onclick={row.getToggleSelectedHandler()}
							data-state={row.getIsSelected() && 'selected'}>
							{#each row.getVisibleCells() as cell (cell.id)}
								<TableCell>
									<FlexRender content={cell.column.columnDef.cell} context={cell.getContext()} />
								</TableCell>
							{/each}
						</TableRow>
					{/each}
				</TableBody>
			</Table>
		</div>
	</CardContent>
	<CardFooter class="justify-end gap-2">
		<Button variant="outline" disabled={!isSelected}>{m.D_SM_SERVER__IDOK()}</Button>
		<Button variant="outline" disabled={!isSelected || rowSelected?.Online_bool}>
			{m.D_SM_SERVER__B_ONLINE()}
		</Button>
		<Button variant="outline" disabled={!isSelected || !rowSelected?.Online_bool}>
			{m.D_SM_SERVER__B_OFFLINE()}
		</Button>
		<Button variant="outline" disabled={!isSelected} onclick={() => (statusOpen = true)}>
			{m.D_SM_SERVER__B_HUB_STATUS()}
		</Button>
		<Button variant="outline">{m.D_SM_SERVER__B_CREATE()}</Button>
		<Button variant="outline" disabled={!isSelected}>{m.D_SM_SERVER__B_EDIT()}</Button>
		<Button variant="destructive" disabled={!isSelected}>{m.D_SM_SERVER__B_DELETE()}</Button>
	</CardFooter>
</Card>

<Status bind:open={statusOpen} hub={rowSelected?.HubName_str} />
