<script lang="ts">
	import { Alert, AlertTitle } from '$lib/components/ui/alert';
	import AlertDescription from '$lib/components/ui/alert/alert-description.svelte';
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import { ButtonGroup } from '$lib/components/ui/button-group';
	import {
		Card,
		CardContent,
		CardHeader,
		CardTitle,
		CardDescription
	} from '$lib/components/ui/card';
	import { createSvelteTable, FlexRender } from '$lib/components/ui/data-table';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import DialogClose from '$lib/components/ui/dialog/dialog-close.svelte';
	import { Input } from '$lib/components/ui/input';
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
	import InfoIcon from '@lucide/svelte/icons/info';
	import * as m from '$lib/paraglide/messages';

	const client = useQueryClient();

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

	const query = createQuery(() => ({
		queryKey: ['listerner'],
		queryFn: async () => {
			let r = await rpc.EnumListener();
			return r.ListenerList;
		},
		initialData: []
	}));

	const createListener = createMutation(() => ({
		mutationFn: rpc.CreateListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: ['listener'] });
		},
		throwOnError: false
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
	let createValue = $state('');
	let valueParsed = $derived(parseInt(createValue));
	let isValidValue = $derived(!isNaN(valueParsed) && 1 <= valueParsed && valueParsed <= 65535);
</script>

<Card class="w-fit">
	<CardHeader>
		<CardTitle>{m.D_SM_SERVER__STATIC1()}</CardTitle>
		<CardDescription>{m.D_SM_SERVER__STATIC2()}</CardDescription>
	</CardHeader>
	<CardContent class="flex">
		<Table>
			<TableHeader>
				{#each table.getHeaderGroups() as headerGroup (headerGroup.id)}
					<TableRow>
						{#each headerGroup.headers as header (header.id)}
							<TableHead colspan={header.colSpan}>
								{#if !header.isPlaceholder}
									<FlexRender
										content={header.column.columnDef.header}
										context={header.getContext()}
									/>
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
						data-state={row.getIsSelected() && 'selected'}
					>
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
				<Button onclick={() => (createOpen = true)} variant="outline"
					>{m.D_SM_SERVER__B_CREATE_LISTENER()}</Button
				>
				<Button disabled={rowSelected == null} variant="outline"
					>{m.D_SM_SERVER__B_DELETE_LISTENER()}</Button
				>
				<Button disabled={!canStart} variant="outline">{m.D_SM_SERVER__B_START()}</Button>
				<Button disabled={!canStop} variant="outline">{m.D_SM_SERVER__B_STOP()}</Button>
			</ButtonGroup>
		</div>
	</CardContent>
</Card>

<Dialog bind:open={createOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>{m.D_SM_CREATE_LISTENER__CAPTION()}</DialogTitle>
			<DialogDescription>
				{m.D_SM_CREATE_LISTENER__STATIC1()}
			</DialogDescription>
		</DialogHeader>
		<div>
			<div class="flex w-full items-center justify-center gap-2">
				{m.D_SM_CREATE_LISTENER__STATIC3()}
				<Input min={1} max={65535} bind:value={createValue} type="number" class="w-24" />
				{m.D_SM_CREATE_LISTENER__STATIC4()}
			</div>
			<Alert class="mt-6">
				<InfoIcon />
				<AlertDescription>
					{m.D_SM_CREATE_LISTENER__STATIC2()}
				</AlertDescription>
			</Alert>
		</div>
		<DialogFooter>
			<Button
				onClickPromise={async () => {
					try {
						await createListener.mutateAsync(
							new VpnRpcListener({ Port_u32: valueParsed, Enable_bool: true })
						);
					} catch {}
				}}
				disabled={!isValidValue}>{m.D_SM_CREATE_LISTENER__IDOK()}</Button
			>
			<DialogClose class={buttonVariants({ variant: 'outline' })}
				>{m.D_SM_CREATE_LISTENER__IDCANCEL()}</DialogClose
			>
		</DialogFooter>
	</DialogContent>
</Dialog>
