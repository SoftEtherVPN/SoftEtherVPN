<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import imageUrl from '../../../../../../../PenCore/Azure.bmp';
	import { rpc, VpnDDnsClientStatus, VpnRpcAzureStatus } from '$lib/rpc';

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

	let azureEnabled = $state<Value>('FALSE');

	$effect(() => {
		azureEnabled = query.data.IsEnabled_bool ? 'TRUE' : 'FALSE';
	});

	let init = false;
	$effect(() => {
		azureEnabled;
		if (!init) {
			init = true;
			return;
		}
		var value = azureEnabled == 'TRUE' ? true : false;
		init = false;
		mutation.mutate({ IsEnabled_bool: value, IsConnected_bool: value });
	});
</script>

<div class="mx-auto max-w-173.75">
	<div class="my-4 ml-4">
		<h1 class="text-2xl font-bold">{m.D_SM_AZURE__CAPTION()}</h1>
	</div>

	<!-- Main settings card -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<figure>
			<img src={imageUrl} alt="Graph explaining azure vpn" />
		</figure>
		<div class="card-body">
			<h2 class="card-title">{m.D_SM_AZURE__S_TITLE()}</h2>
			<span>{m.D_SM_AZURE__S_1()}</span>
			<span>{m.D_SM_AZURE__S_2()}</span>
			<span>{m.D_SM_AZURE__S_3()}</span>
			<div class="grid grid-cols-3 gap-4">
				<fieldset
					class="fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
					<legend class="fieldset-legend">{m.D_SM_AZURE__B_BOLD()}</legend>

					<label for="azure-enable" class="label text-base-content">
						<input
							id="azure-enable"
							bind:group={azureEnabled}
							type="radio"
							value="TRUE"
							class="radio" />
						{m.D_SM_AZURE__R_ENABLE()}
					</label>
					<span class="label ml-7.5 text-base-content">
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
							class="radio" />
						{m.D_SM_AZURE__R_DISABLE()}
					</label>
				</fieldset>
				{#if query.data.IsEnabled_bool}
					<fieldset
						class="col-span-2 fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
						<legend class="fieldset-legend">{m.D_SM_AZURE__S_HOSTNAME_BORDER()}</legend>
						<span>{m.D_SM_AZURE__S_HOSTNAME_INFO()}</span>
						<div class="flex justify-between">
							<span class="self-center text-base">
								{ddnsQuery.data.CurrentFqdn_str.replace('softether.net', 'vpnazure.net')}
							</span>
							<a href="#/ddns" class="btn btn-sm btn-outline">
								{m.D_SM_AZURE__B_CHANGE()}
							</a>
						</div>
					</fieldset>
				{/if}
			</div>
			<div class="card-actions justify-end">
				<a
					class="btn btn-sm btn-neutral not-dark:btn-soft"
					href="https://selinks.org/?vpnazure"
					target="_blank">
					{m.D_SM_AZURE__B_WEB()}
				</a>
				<a href="#/" class="btn btn-sm btn-primary">{m.D_SM_AZURE__IDCANCEL()}</a>
			</div>
		</div>
	</div>
</div>
