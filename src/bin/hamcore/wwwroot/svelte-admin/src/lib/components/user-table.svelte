<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { isDefaultDate } from '$lib/rpc/dates';
	import { m } from '$lib/paraglide/messages';
	import { datetime } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import type { VpnRpcEnumUserItem } from '$lib/rpc';
	import { translateAuthType } from '$lib/rpc/labels';
	import DataTable, { type DataTableColumn } from './ui/data-table.svelte';

	interface Props {
		hub: string;
		users: VpnRpcEnumUserItem[];
		/** Name of the selected user, or `undefined`. Bindable. */
		selectedId?: string | number;
		loading?: boolean;
		rowsPerPage?: number;
		searchable?: boolean;
		class?: string;
		tableClass?: string;
	}

	let {
		hub,
		users,
		selectedId = $bindable(),
		loading = false,
		rowsPerPage = 15,
		searchable = true,
		class: className,
		tableClass = 'table-pin-rows'
	}: Props = $props();

	const locale = getLocale();

	const columns: DataTableColumn<VpnRpcEnumUserItem>[] = $derived([
		{ header: m.SM_USER_COLUMN_1(), value: 'Name_str', primary: true },
		{ header: m.SM_USER_COLUMN_2(), value: 'Realname_utf' },
		{
			header: m.SM_USER_COLUMN_3(),
			value: (user) => user.GroupName_str || '-',
			sortBy: 'GroupName_str'
		},
		{ header: m.SM_USER_COLUMN_4(), value: 'Note_utf', cardSpan: 2 },
		{
			header: m.SM_USER_COLUMN_5(),
			value: (user) => translateAuthType(user.AuthType_u32),
			sortBy: 'AuthType_u32'
		},
		{ header: m.SM_USER_COLUMN_6(), value: 'NumLogin_u32' },
		{
			header: m.SM_USER_COLUMN_7(),
			value: (user) =>
				isDefaultDate(user.LastLoginTime_dt)
					? '(None)'
					: datetime(locale, user.LastLoginTime_dt, {
							dateStyle: 'medium',
							timeStyle: 'medium'
						}),
			sortBy: 'LastLoginTime_dt',
			cardSpan: 2
		}
	]);

	async function navigate(row: VpnRpcEnumUserItem) {
		await goto(resolve('/hub/[name]/users/[user]', { name: hub, user: row.Name_str }));
	}
</script>

<DataTable
	rows={users}
	{columns}
	rowKey={(user) => user.Name_str}
	bind:selectedKey={selectedId}
	{loading}
	{rowsPerPage}
	{searchable}
	{tableClass}
	class={className}
	onrowdblclick={navigate} />
