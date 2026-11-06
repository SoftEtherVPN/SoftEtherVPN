<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createQuery, useQueryClient } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcEnumSession, VpnRpcEnumSessionItem } from '$lib/rpc';
	import { hubKeys } from '$lib/rpc/query-keys';
	import type { DataTableColumn } from '$lib/components/ui/data-table.svelte';
	import DataTable from '$lib/components/ui/data-table.svelte';
	import { number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';

	let { params }: PageProps = $props();

	const locale = getLocale();
	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.session(params.name),
		queryFn: () => rpc.EnumSession(new VpnRpcEnumSession({ HubName_str: params.name })),
		initialData: new VpnRpcEnumSession(),
		refetchInterval: 5000
	}));

	const columns: DataTableColumn<VpnRpcEnumSessionItem>[] = [
		{ header: m.SM_SESS_COLUMN_1(), value: 'Name_str' },
		{ header: m.SM_SESS_COLUMN_8(), value: 'VLanId_u32' },
		{ header: m.SM_SESS_COLUMN_3(), value: 'Username_str' },
		{ header: m.SM_SESS_COLUMN_5(), value: 'CurrentNumTcp_u32' },
		{
			header: m.SM_SESS_COLUMN_6(),
			value: (u) => number(locale, u.PacketSize_u64),
			sortBy: 'PacketSize_u64'
		},
		{
			header: m.SM_SESS_COLUMN_7(),
			value: (u) => number(locale, u.PacketNum_u64),
			sortBy: 'PacketNum_u64'
		}
	];
</script>

<div class="p-4">
	<h2 class="text-xl font-bold">{m.D_SM_SESSION__CAPTION({ input0: params.name })}</h2>
	<span class="text-sm font-light">{m.D_SM_SESSION__S_TITLE({ input0: params.name })}</span>

	<DataTable
		rows={query.data?.SessionList}
		{columns}
		rowKey={(user) => user.Name_str}
		loading={query.isLoading} />
</div>
