<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import imageUrl from '../../../../../../../PenCore/Azure.bmp';
	import { rpc, VpnDDnsClientStatus, VpnRpcAzureStatus } from '$lib/rpc';
	import PageHeader from '$lib/components/page-header.svelte';
	import CloudIcon from '@lucide/svelte/icons/cloud';

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: ['azure'],
		queryFn: rpc.GetAzureStatus,
		initialData: new VpnRpcAzureStatus()
	}));

	const ddnsQuery = createQuery(() => ({
		queryKey: ['ddns'],
		queryFn: rpc.GetDDnsClientStatus,
		initialData: new VpnDDnsClientStatus()
	}));

	const mutation = createMutation(() => ({
		mutationFn: rpc.SetAzureStatus,
		async onSuccess(r) {
			client.setQueryData(['azure'], r);
		}
	}));

	type Value = 'TRUE' | 'FALSE';

	let azureEnabled = $derived<Value>(query.data.IsEnabled_bool ? 'TRUE' : 'FALSE');

	function setEnabled(value: Value) {
		const enabled = value === 'TRUE';
		mutation.mutate({ IsEnabled_bool: enabled, IsConnected_bool: enabled });
	}
</script>

<div class="mx-auto mt-4 max-w-173.75">
	<PageHeader title={m.D_SM_AZURE__CAPTION()}>
		{#snippet icon()}
			<CloudIcon size={22} />
		{/snippet}
		{#snippet actions()}
			{#if query.data.IsEnabled_bool}
				<span
					class={[
						'badge gap-1.5 badge-soft',
						query.data.IsConnected_bool ? 'badge-success' : 'badge-warning'
					]}>
					<span
						class={['status', query.data.IsConnected_bool ? 'status-success' : 'status-warning']}>
					</span>
					{query.data.IsConnected_bool
						? m.SM_AZURE_STATUS_CONNECTED()
						: m.SM_AZURE_STATUS_NOT_CONNECTED()}
				</span>
			{/if}
		{/snippet}
	</PageHeader>

	<!-- Main settings card -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<figure class="border-b border-base-300 dark:border-base-100">
			<img src={imageUrl} alt="Graph explaining azure vpn" />
		</figure>
		<div class="card-body">
			<h2 class="card-title">{m.D_SM_AZURE__S_TITLE()}</h2>
			<div class="flex flex-col gap-1 text-sm leading-relaxed opacity-70">
				<span>{m.D_SM_AZURE__S_1()}</span>
				<span>{m.D_SM_AZURE__S_2()}</span>
				<span>{m.D_SM_AZURE__S_3()}</span>
			</div>
			<div class="mt-2 grid gap-4 md:grid-cols-3">
				<fieldset
					class="fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
					<legend class="fieldset-legend">{m.D_SM_AZURE__B_BOLD()}</legend>

					<label for="azure-enable" class="label text-base-content">
						<input
							id="azure-enable"
							bind:group={azureEnabled}
							type="radio"
							value="TRUE"
							class="radio"
							onchange={() => setEnabled('TRUE')} />
						{m.D_SM_AZURE__R_ENABLE()}
					</label>
					<span class="label ms-7.5 flex items-center gap-1.5 text-base-content">
						<span
							class={[
								'status',
								query.data.IsEnabled_bool && query.data.IsConnected_bool
									? 'status-success'
									: 'status-warning'
							]}>
						</span>
						{query.data.IsConnected_bool
							? m.SM_AZURE_STATUS_CONNECTED()
							: m.SM_AZURE_STATUS_NOT_CONNECTED()}
					</span>
					<label for="azure-disable" class="label text-base-content">
						<input
							id="azure-disable"
							bind:group={azureEnabled}
							type="radio"
							value="FALSE"
							class="radio"
							onchange={() => setEnabled('FALSE')} />
						{m.D_SM_AZURE__R_DISABLE()}
					</label>
				</fieldset>
				{#if query.data.IsEnabled_bool}
					<fieldset
						class="col-span-2 fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
						<legend class="fieldset-legend">{m.D_SM_AZURE__S_HOSTNAME_BORDER()}</legend>
						<span>{m.D_SM_AZURE__S_HOSTNAME_INFO()}</span>
						<div class="justify-between md:flex">
							<span class="self-center text-base">
								{ddnsQuery.data.CurrentFqdn_str.replace('softether.net', 'vpnazure.net')}
							</span>
							<a href="#/ddns" class="btn btn-outline btn-sm max-md:mt-4">
								{m.D_SM_AZURE__B_CHANGE()}
							</a>
						</div>
					</fieldset>
				{/if}
			</div>
			<div class="card-actions justify-end">
				<a
					class="btn btn-neutral btn-sm not-dark:btn-soft"
					href="https://selinks.org/?vpnazure"
					target="_blank">
					{m.D_SM_AZURE__B_WEB()}
				</a>
				<a href="#/" class="btn btn-primary btn-sm">{m.D_SM_AZURE__IDCANCEL()}</a>
			</div>
		</div>
	</div>
</div>
