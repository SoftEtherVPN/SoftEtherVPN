<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { datetime } from '$lib/paraglide/registry';
	import { createQuery } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcEnumUser, VpnRpcEnumUserItem } from '$lib/rpc';
	import { getLocale } from '$lib/paraglide/runtime';
	import { isDefaultDate } from '$lib/helpers';
	import { translateAuthType } from '$lib/translation';

	let { params }: PageProps = $props();

	const locale = getLocale();
	const query = createQuery(() => ({
		queryKey: ['hub', params.name, 'users'],
		queryFn: ({ queryKey }) => rpc.EnumUser(new VpnRpcEnumUser({ HubName_str: queryKey[1] })),
		initialData: new VpnRpcEnumUser()
	}));

	let selectedKey = $state<string | undefined>(undefined);
	let selected = $derived(
		selectedKey ? query.data.UserList.find((r) => r.Name_str == selectedKey) : undefined
	);

	function select(row: VpnRpcEnumUserItem) {
		if (selected?.Name_str == row.Name_str) selectedKey = undefined;
		else selectedKey = row.Name_str;
	}

	function refresh() {
		query.refetch();
	}
</script>

<div class="grid h-full grid-rows-[auto_1fr_auto] p-4">
	<div>
		<h2 class="text-xl font-bold">{m.D_SM_USER__CAPTION()}</h2>
		<span class="text-sm font-light">{m.D_SM_USER__S_TITLE({ input0: params.name })}</span>
	</div>

	<div class="max-h-[75vh] overflow-y-auto">
		<table class="table-pin-rows table">
			<thead>
				<tr>
					<th>{m.SM_USER_COLUMN_1()}</th>
					<th>{m.SM_USER_COLUMN_2()}</th>
					<th>{m.SM_USER_COLUMN_3()}</th>
					<th>{m.SM_USER_COLUMN_4()}</th>
					<th>{m.SM_USER_COLUMN_5()}</th>
					<th>{m.SM_USER_COLUMN_6()}</th>
					<th>{m.SM_USER_COLUMN_7()}</th>
				</tr>
			</thead>
			<tbody>
				{#each query.data.UserList as user (user.Name_str)}
					<tr
						class={{ 'bg-base-300 dark:bg-base-100': selected?.Name_str == user.Name_str }}
						onclick={() => select(user)}>
						<td>{user.Name_str}</td>
						<td>{user.Realname_utf}</td>
						<td>{user.GroupName_str || '-'}</td>
						<td>{user.Note_utf}</td>
						<td>{translateAuthType(user.AuthType_u32)}</td>
						<td>{user.NumLogin_u32}</td>
						<td>
							{isDefaultDate(user.LastLoginTime_dt)
								? '(None)'
								: datetime(locale, user.LastLoginTime_dt, {
										dateStyle: 'medium',
										timeStyle: 'medium'
									})}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<div class="flex justify-end gap-2">
		<button class="btn btn-sm btn-primary">{m.D_SM_USER__B_CREATE()}</button>
		<button disabled={!selected} class="btn btn-sm btn-accent">{m.D_SM_USER__IDOK()}</button>
		<button disabled={!selected} class="btn btn-sm btn-neutral">{m.D_SM_USER__B_STATUS()}</button>
		<button disabled={!selected} class="btn btn-sm btn-error">{m.D_SM_USER__B_DELETE()}</button>
		<button class="btn btn-sm" onclick={refresh}>{m.D_SM_USER__B_REFRESH()}</button>
	</div>
</div>
