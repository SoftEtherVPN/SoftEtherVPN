<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { ButtonGroup } from '$lib/components/ui/button-group';
	import {
		Card,
		CardContent,
		CardHeader,
		CardTitle,
		CardDescription
	} from '$lib/components/ui/card';
	import { createSvelteTable, FlexRender } from '$lib/components/ui/data-table';
	import { Separator } from '$lib/components/ui/separator';
	import {
		Table,
		TableBody,
		TableCell,
		TableHead,
		TableHeader,
		TableRow
	} from '$lib/components/ui/table';
	import { rpc, VpnRpcListener, type VpnRpcListenerListItem } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { getCoreRowModel, type RowSelectionState, type ColumnDef } from '@tanstack/table-core';
	import * as m from '$lib/paraglide/messages';
	import CreateModal from './listerner/create-modal.svelte';
	import StopModal from './listerner/stop-modal.svelte';
	import DeleteModal from './listerner/delete-modal.svelte';

	const columns: ColumnDef<VpnRpcListenerListItem>[] = [
		{ accessorKey: 'Ports_u32', header: m.CM_LISTENER_COLUMN_1() },
		{
			accessorFn: (r) => {
				if (r.Errors_bool) return m.CM_LISTENER_ERROR();
				if (!r.Enables_bool) return m.CM_LISTENER_OFFLINE();
				return m.CM_LISTENER_ONLINE();
			},
			header: m.CM_LISTENER_COLUMN_2()
		}
	];

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: ['listener'],
		queryFn: async () => {
			let r = await rpc.EnumListener();
			return r.ListenerList;
		},
		initialData: []
	}));

	let rowSelection = $state<RowSelectionState>({});
	const table = createSvelteTable({
		get data() {
			return query.data;
		},
		getRowId: (r) => r.Ports_u32.toString(),
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

	let rowSelected = $derived.by(() => query.data.find((r) => rowSelection[r.Ports_u32.toString()]));
	let canStart = $derived(rowSelected != null && !rowSelected.Enables_bool);
	let canStop = $derived(rowSelected != null && rowSelected.Enables_bool);

	let createOpen = $state(false);
	let stopOpen = $state(false);
	let deleteOpen = $state(false);

	const startListener = createMutation(() => ({
		mutationFn: rpc.EnableListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: ['listener'] });
		}
	}));

	function start() {
		return startListener.mutateAsync(
			new VpnRpcListener({ Port_u32: rowSelected?.Ports_u32, Enable_bool: true })
		);
	}
</script>

<Card class="w-fit">
	<CardHeader>
		<CardTitle>{m.D_SM_SERVER__STATIC1()}</CardTitle>
		<CardDescription>{m.D_SM_SERVER__STATIC2()}</CardDescription>
	</CardHeader>
	<CardContent class="flex max-h-48">
		<Table class="">
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
		<Separator class="mx-4" orientation="vertical" />
		<div class="flex">
			<ButtonGroup class="justify-center" orientation="vertical">
				<Button onclick={() => (createOpen = true)} variant="outline">
					{m.D_SM_SERVER__B_CREATE_LISTENER()}
				</Button>
				<Button
					disabled={rowSelected == null}
					variant="outline"
					onclick={() => (deleteOpen = true)}>
					{m.D_SM_SERVER__B_DELETE_LISTENER()}
				</Button>
				<Button disabled={!canStart} variant="outline" onClickPromise={start}>
					{m.D_SM_SERVER__B_START()}
				</Button>
				<Button disabled={!canStop} variant="outline" onclick={() => (stopOpen = true)}>
					{m.D_SM_SERVER__B_STOP()}
				</Button>
			</ButtonGroup>
		</div>
	</CardContent>
</Card>

<CreateModal bind:open={createOpen} />
<StopModal bind:open={stopOpen} port={rowSelected?.Ports_u32 ?? 0} />
<DeleteModal bind:open={deleteOpen} port={rowSelected?.Ports_u32 ?? 0} />
