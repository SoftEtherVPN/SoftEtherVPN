<script lang="ts">
	import { isDefaultDate } from '$lib/helpers';
	import { m } from '$lib/paraglide/messages';
	import { datetime } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import type { VpnRpcEnumUserItem } from '$lib/rpc';
	import { translateAuthType } from '$lib/translation';
	import type { HTMLTableAttributes } from 'svelte/elements';

	interface Props extends HTMLTableAttributes {
		users: VpnRpcEnumUserItem[];
		selectedId?: string;
	}

	let { users, selectedId = $bindable(), ...rest }: Props = $props();

	function select(row: VpnRpcEnumUserItem) {
		if (selectedId == row.Name_str) selectedId = undefined;
		else selectedId = row.Name_str;
	}

	const locale = getLocale();
</script>

<table {...rest} class={['table-pin-rows table', rest.class]}>
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
		{#each users as user (user.Name_str)}
			<tr
				class="hover:bg-base-300"
				class:bg-base-200={selectedId == user.Name_str}
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
