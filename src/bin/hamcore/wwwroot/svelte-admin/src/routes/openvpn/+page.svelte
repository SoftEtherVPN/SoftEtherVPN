<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnOpenVpnSstpConfig, Util_Base64_Decode } from '$lib/rpc';
	import { openVpnKeys } from '$lib/queryKeys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, Label } from 'formsnap';
	import Button from '$lib/components/button.svelte';
	import PageHeader from '$lib/components/page-header.svelte';
	import RouteIcon from '@lucide/svelte/icons/route';
	import DownloadIcon from '@lucide/svelte/icons/download';
	import { goto } from '$app/navigation';

	const client = useQueryClient();

	// ── Query ─────────────────────────────────────────────────────────────────

	const openvpnQuery = createQuery(() => ({
		queryKey: openVpnKeys.config(),
		queryFn: rpc.GetOpenVpnSstpConfig
	}));

	// ── Save mutation ─────────────────────────────────────────────────────────

	const saveMutation = createMutation(() => ({
		mutationFn: (data: VpnOpenVpnSstpConfig) => rpc.SetOpenVpnSstpConfig(data),
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: openVpnKeys.all });
			await goto('#/');
		}
	}));

	// ── Schema ────────────────────────────────────────────────────────────────

	const schema = z.object({
		EnableOpenVPN_bool: z.boolean(),
		EnableSSTP_bool: z.boolean()
	});

	// ── SuperForm ─────────────────────────────────────────────────────────────

	const sf = superForm(defaults(zod4(schema)), {
		SPA: true,
		validators: zod4Client(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await saveMutation.mutateAsync(
					new VpnOpenVpnSstpConfig({
						EnableOpenVPN_bool: form.data.EnableOpenVPN_bool,
						OpenVPNPortList_str: '1194',
						EnableSSTP_bool: form.data.EnableSSTP_bool
					})
				);
			}
		}
	});
	const { form, enhance, submitting } = sf;

	// Sync query data → form
	$effect(() => {
		const data = openvpnQuery.data;
		if (data) {
			form.update(
				($form) => {
					$form.EnableOpenVPN_bool = data.EnableOpenVPN_bool;
					$form.EnableSSTP_bool = data.EnableSSTP_bool;
					return $form;
				},
				{ taint: 'untaint-all' }
			);
		}
	});

	// ── Generate config file download ─────────────────────────────────────────

	async function generateConfig() {
		const result = await rpc.MakeOpenVpnConfigFile();
		const blob = new Blob([Util_Base64_Decode(result.Buffer_bin)], { type: 'application/zip' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = result.FilePath_str || 'openvpn-config.zip';
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<div class="mx-auto mt-4 max-w-3xl">
	<PageHeader title={m.D_SM_OPENVPN__S_TITLE()}>
		{#snippet icon()}
			<RouteIcon size={22} />
		{/snippet}
	</PageHeader>

	<!-- Main settings card -->
	<div class="card bg-base-100 shadow dark:bg-base-300">
		<div class="card-body">
			{#if openvpnQuery.isLoading}
				<div class="flex flex-col gap-4 py-2">
					<div class="h-6 w-56 skeleton"></div>
					<div class="h-4 w-full max-w-md skeleton"></div>
					<div class="h-9 w-full skeleton"></div>
					<div class="h-9 w-2/3 skeleton"></div>
				</div>
			{:else}
				<form use:enhance>
					<!-- Section: OpenVPN Clone Server Function -->
					<fieldset class="fieldset">
						<legend class="fieldset-legend text-xl">{m.D_SM_OPENVPN__S_13()}</legend>
						<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_1()}</p>

						<Field form={sf} name="EnableOpenVPN_bool">
							<Control>
								{#snippet children({ props })}
									<Label class="label">
										<input
											{...props}
											type="checkbox"
											class="toggle toggle-sm"
											bind:checked={$form.EnableOpenVPN_bool} />
										{m.D_SM_OPENVPN__R_OPENVPN()}
									</Label>
								{/snippet}
							</Control>
						</Field>
					</fieldset>

					<div class="divider"></div>

					<!-- Section: Sample File Generating Tool -->
					<fieldset class="fieldset">
						<legend class="fieldset-legend text-xl">{m.D_SM_OPENVPN__S_TOOL()}</legend>
						<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_TOOL2()}</p>

						<Button
							type="button"
							class="btn mt-1 w-fit gap-2 btn-neutral btn-sm not-dark:btn-soft"
							onclick={generateConfig}>
							<DownloadIcon size={16} />
							{m.D_SM_OPENVPN__B_CONFIG()}
						</Button>
					</fieldset>

					<div class="divider"></div>

					<!-- Section: MS-SSTP Clone Server Function -->
					<fieldset class="fieldset">
						<legend class="fieldset-legend text-xl">{m.D_SM_OPENVPN__S_2()}</legend>
						<span class="text-sm opacity-70">{m.D_SM_OPENVPN__S_3()}</span>

						<Field form={sf} name="EnableSSTP_bool">
							<Control>
								{#snippet children({ props })}
									<Label class="label">
										<input
											{...props}
											type="checkbox"
											class="toggle toggle-sm"
											bind:checked={$form.EnableSSTP_bool} />
										{m.D_SM_OPENVPN__R_SSTP()}
									</Label>
								{/snippet}
							</Control>
						</Field>

						{#if $form.EnableSSTP_bool}
							<p class="label ms-10 whitespace-normal">{m.D_SM_OPENVPN__S_SSTP()}</p>
						{/if}
					</fieldset>

					<div class="divider"></div>

					<!-- Footer note + buttons -->
					<div class="flex flex-col gap-3">
						<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_4()}</p>
						<div class="flex flex-wrap items-center justify-end gap-2">
							<a href="#/ipsec" class="btn me-auto btn-neutral btn-sm not-dark:btn-soft">
								{m.D_SM_OPENVPN__B_IPSEC()}
							</a>
							<a href="#/" class="btn btn-neutral btn-sm not-dark:btn-soft">
								{m.D_SM_OPENVPN__IDCANCEL()}
							</a>
							<Button
								type="submit"
								class="btn btn-primary btn-sm"
								loading={$submitting || saveMutation.isPending}
								disabled={$submitting || saveMutation.isPending}>
								{m.D_SM_OPENVPN__IDOK()}
							</Button>
						</div>
					</div>
				</form>
			{/if}
		</div>
	</div>
</div>
