<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnOpenVpnSstpConfig, Util_Base64_Decode } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, FieldErrors, Label } from 'formsnap';
	import Button from '$lib/components/button.svelte';

	const client = useQueryClient();

	// ── Query ─────────────────────────────────────────────────────────────────

	const openvpnQuery = createQuery(() => ({
		queryKey: ['openvpn'],
		queryFn: rpc.GetOpenVpnSstpConfig
	}));

	// ── Save mutation ─────────────────────────────────────────────────────────

	const saveMutation = createMutation(() => ({
		mutationFn: (data: VpnOpenVpnSstpConfig) => rpc.SetOpenVpnSstpConfig(data),
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: ['openvpn'] });
		}
	}));

	// ── Schema ────────────────────────────────────────────────────────────────

	const schema = z.object({
		EnableOpenVPN_bool: z.boolean(),
		OpenVPNPortList_str: z.string().min(1),
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
						OpenVPNPortList_str: form.data.OpenVPNPortList_str,
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
					$form.OpenVPNPortList_str = data.OpenVPNPortList_str;
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

<!-- Title -->
<div class="my-4 ml-4">
	<h1 class="text-2xl font-bold">{m.D_SM_OPENVPN__S_TITLE()}</h1>
</div>

<!-- Main settings card -->
<div class="card bg-base-100 shadow dark:bg-base-300">
	<div class="card-body">
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
									class="checkbox checkbox-sm"
									bind:checked={$form.EnableOpenVPN_bool} />
								{m.D_SM_OPENVPN__R_OPENVPN()}
							</Label>
						{/snippet}
					</Control>
				</Field>

				<!-- UDP Ports -->
				<Field form={sf} name="OpenVPNPortList_str">
					<Control>
						{#snippet children({ props })}
							<Label class="label">UDP Ports to Listen for OpenVPN:</Label>
							<div class="flex items-center gap-2">
								<input
									{...props}
									type="text"
									class="input input-sm w-48"
									disabled={!$form.EnableOpenVPN_bool}
									bind:value={$form.OpenVPNPortList_str} />
								<button
									type="button"
									class="btn btn-sm btn-neutral not-dark:btn-soft"
									disabled={!$form.EnableOpenVPN_bool}
									onclick={() => ($form.OpenVPNPortList_str = '1194')}>
									Restore Default
								</button>
							</div>
						{/snippet}
					</Control>
					<FieldErrors class="text-xs text-error" />
					<span class="label text-wrap lg:max-w-2/3">
						{m.CMD_PortsUDPSet_Help()}
					</span>
				</Field>
			</fieldset>

			<div class="divider"></div>

			<!-- Section: Sample File Generating Tool -->
			<fieldset class="fieldset">
				<legend class="fieldset-legend text-xl">{m.D_SM_OPENVPN__S_TOOL()}</legend>
				<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_TOOL2()}</p>

				<Button
					type="button"
					class="btn mt-1 w-fit btn-sm btn-neutral not-dark:btn-soft"
					onclick={generateConfig}>
					{m.D_SM_OPENVPN__B_CONFIG()}
				</Button>
			</fieldset>

			<div class="divider"></div>

			<!-- Section: MS-SSTP Clone Server Function -->
			<fieldset class="fieldset">
				<legend class="fieldset-legend text-xl">{m.D_SM_OPENVPN__S_2()}</legend>
				<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_3()}</p>

				<Field form={sf} name="EnableSSTP_bool">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="checkbox checkbox-sm"
									bind:checked={$form.EnableSSTP_bool} />
								{m.D_SM_OPENVPN__R_SSTP()}
							</Label>
						{/snippet}
					</Control>
				</Field>

				{#if $form.EnableSSTP_bool}
					<p class="label ml-7">{m.D_SM_OPENVPN__S_SSTP()}</p>
				{/if}
			</fieldset>

			<div class="divider"></div>

			<!-- Footer note + buttons -->
			<div class="flex flex-col gap-3">
				<p class="text-sm opacity-70">{m.D_SM_OPENVPN__S_4()}</p>
				<div class="flex flex-wrap items-center justify-end gap-2">
					<a href="#/ipsec" class="btn mr-auto btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_OPENVPN__B_IPSEC()}
					</a>
					<a href="#/" class="btn btn-sm btn-neutral not-dark:btn-soft">
						{m.D_SM_OPENVPN__IDCANCEL()}
					</a>
					<Button
						type="submit"
						class="btn btn-sm btn-primary"
						loading={$submitting || saveMutation.isPending}
						disabled={$submitting || saveMutation.isPending}>
						{m.D_SM_OPENVPN__IDOK()}
					</Button>
				</div>
			</div>
		</form>
	</div>
</div>
