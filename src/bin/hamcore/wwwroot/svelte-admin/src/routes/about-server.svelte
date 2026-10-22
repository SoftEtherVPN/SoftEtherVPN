<script lang="ts">
	import Modal from '$lib/components/ui/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { serverKeys } from '$lib/rpc/query-keys';
	import { rpc, VpnCapslist, VpnRpcServerInfo } from '$lib/rpc';
	import { translateBoolean, TranslateCap, translateServerType } from '$lib/rpc/labels';
	import { createQuery } from '@tanstack/svelte-query';
	import ServerIcon from '@lucide/svelte/icons/server';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	let query = createQuery(() => ({
		queryKey: serverKeys.info(),
		queryFn: rpc.GetServerInfo,
		initialData: new VpnRpcServerInfo(),
		enabled: open
	}));

	let capsQuery = createQuery(() => ({
		queryKey: serverKeys.caps(),
		queryFn: rpc.GetCaps,
		initialData: new VpnCapslist(),
		select: (caps) =>
			caps.CapsList.filter(
				(elem, index) =>
					caps.CapsList.findIndex((obj) => obj.CapsName_str == elem.CapsName_str) === index
			),
		enabled: open
	}));
</script>

<Modal class="*:first:max-w-2xl" bind:open>
	<div class="max-h-[70vh]">
		<div class="mb-3 flex items-center gap-2">
			<span class="grid size-9 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
				<ServerIcon size={18} />
			</span>
			<h3 class="text-lg font-semibold">{m.SM_INFO_TITLE()}</h3>
			{#if query.isFetching}
				<span class="loading loading-xs loading-spinner opacity-60"></span>
			{/if}
		</div>

		<div class="overflow-x-auto">
			<table class="table table-pin-rows table-zebra table-sm">
				<thead>
					<tr>
						<th>{m.SM_STATUS_COLUMN_1()}</th>
						<th>{m.SM_STATUS_COLUMN_2()}</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td>{m.SM_INFO_PRODUCT_NAME()}</td>
						<td>{query.data.ServerProductName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_INFO_VERSION()}</td>
						<td>{query.data.ServerVersionString_str}</td>
					</tr>
					<tr>
						<td>{m.SM_INFO_BUILD()}</td>
						<td>{query.data.ServerBuildInfoString_str}</td>
					</tr>
					<tr>
						<td>{m.SM_INFO_HOSTNAME()}</td>
						<td>{query.data.ServerHostName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_ST_SERVER_TYPE()}</td>
						<td>{translateServerType(query.data.ServerType_u32)}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_SYSTEM_NAME()}</td>
						<td>{query.data.OsSystemName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_PRODUCT_NAME()}</td>
						<td>{query.data.OsProductName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_VENDER_NAME()}</td>
						<td>{query.data.OsVendorName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_VERSION()}</td>
						<td>{query.data.OsVersion_str}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_KERNEL_NAME()}</td>
						<td>{query.data.KernelName_str}</td>
					</tr>
					<tr>
						<td>{m.SM_OS_KERNEL_VERSION()}</td>
						<td>{query.data.KernelVersion_str}</td>
					</tr>
					{#each capsQuery.data as cap (cap.CapsName_str)}
						{@const isBool = cap.CapsName_str[0] == 'b'}
						<tr>
							<td>{TranslateCap(cap.CapsName_str) ?? cap.CapsDescrption_utf}</td>
							<td>{isBool ? translateBoolean(cap.CapsValue_u32 == 1) : cap.CapsValue_u32}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</div>
</Modal>
