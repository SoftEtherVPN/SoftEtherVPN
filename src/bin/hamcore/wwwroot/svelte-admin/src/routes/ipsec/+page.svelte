<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnIPsecServices } from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, FieldErrors, Label } from 'formsnap';
	import Button from '$lib/components/button.svelte';
	import Detail from './detail.svelte';
	import Info from '@lucide/svelte/icons/info';

	const client = useQueryClient();

	// ── Queries ──────────────────────────────────────────────────────────────

	const ipsecQuery = createQuery(() => ({
		queryKey: ['ipsec'],
		queryFn: rpc.GetIPsecServices
	}));

	const hubQuery = createQuery(() => ({
		queryKey: ['ipsec', 'hubs'],
		queryFn: async () => (await rpc.EnumHub()).HubList,
		initialData: []
	}));

	// ── Main settings schema ──────────────────────────────────────────────────

	const mainSchema = z.object({
		L2TP_IPsec_bool: z.boolean(),
		L2TP_Raw_bool: z.boolean(),
		EtherIP_IPsec_bool: z.boolean(),
		IPsec_Secret_str: z.string().min(1),
		L2TP_DefaultHub_str: z.string()
	});

	// ── Save mutation ─────────────────────────────────────────────────────────

	const saveMutation = createMutation(() => ({
		mutationFn: (data: VpnIPsecServices) => rpc.SetIPsecServices(data),
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: ['ipsec'] });
		}
	}));

	// ── Main superForm ────────────────────────────────────────────────────────

	const sf = superForm(defaults(zod4(mainSchema)), {
		SPA: true,
		validators: zod4Client(mainSchema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await saveMutation.mutateAsync(
					new VpnIPsecServices({
						L2TP_IPsec_bool: form.data.L2TP_IPsec_bool,
						L2TP_Raw_bool: form.data.L2TP_Raw_bool,
						EtherIP_IPsec_bool: form.data.EtherIP_IPsec_bool,
						IPsec_Secret_str: form.data.IPsec_Secret_str,
						L2TP_DefaultHub_str: form.data.L2TP_DefaultHub_str
					})
				);
			}
		}
	});
	const { form, enhance, submitting } = sf;

	// Sync query data → form when loaded
	$effect(() => {
		$inspect.trace();
		const data = ipsecQuery.data;
		if (data) {
			form.update(
				($form) => {
					$form.L2TP_IPsec_bool = data.L2TP_IPsec_bool;
					$form.L2TP_Raw_bool = data.L2TP_Raw_bool;
					$form.EtherIP_IPsec_bool = data.EtherIP_IPsec_bool;
					$form.IPsec_Secret_str = data.IPsec_Secret_str;
					$form.L2TP_DefaultHub_str = data.L2TP_DefaultHub_str;
					return $form;
				},
				{ taint: 'untaint-all' }
			);
		}
	});
</script>

<!-- Title + description -->
<div class="my-4 ml-4">
	<h1 class="text-2xl font-bold">{m.D_SM_IPSEC__S_TITLE()}</h1>
	<p class="mt-1 text-sm opacity-70">{m.D_SM_IPSEC__S_3()}</p>
</div>

<!-- Main settings card -->
<div class="card bg-base-100 shadow dark:bg-base-300">
	<div class="card-body">
		<form use:enhance>
			<!-- Section: L2TP -->
			<fieldset class="fieldset">
				<legend class="fieldset-legend text-xl">{m.D_SM_IPSEC__S01()}</legend>
				<p class="text-sm opacity-70">{m.D_SM_IPSEC__S02()}</p>

				<Field form={sf} name="L2TP_IPsec_bool">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="checkbox checkbox-sm"
									bind:checked={$form.L2TP_IPsec_bool} />
								{m.D_SM_IPSEC__R_L2TP_OVER_IPSEC()}
							</Label>
							<p class="label ml-7">{m.D_SM_IPSEC__S03()}</p>
						{/snippet}
					</Control>
				</Field>

				<Field form={sf} name="L2TP_Raw_bool">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="checkbox checkbox-sm"
									bind:checked={$form.L2TP_Raw_bool} />
								{m.D_SM_IPSEC__R_L2TP_RAW()}
							</Label>
							<p class="label ml-7">{m.D_SM_IPSEC__S04()}</p>
						{/snippet}
					</Control>
				</Field>

				<!-- Info note: Username@HubName format -->
				<div class="alert w-max alert-soft alert-info">
					<Info />
					{m.D_SM_IPSEC__S_2()}
				</div>

				<Field form={sf} name="L2TP_DefaultHub_str">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								{m.D_SM_IPSEC__S_1()}
							</Label>
							<select
								{...props}
								class="select w-full max-w-xs select-sm"
								bind:value={$form.L2TP_DefaultHub_str}>
								{#each hubQuery.data as hub (hub.HubName_str)}
									<option value={hub.HubName_str}>{hub.HubName_str}</option>
								{/each}
							</select>
						{/snippet}
					</Control>
				</Field>
			</fieldset>

			<div class="divider"></div>

			<!-- Section: EtherIP -->
			<fieldset class="fieldset">
				<legend class="fieldset-legend text-xl">{m.D_SM_IPSEC__S05()}</legend>
				<p class="text-sm opacity-70">{m.D_SM_IPSEC__S06()}</p>

				<Field form={sf} name="EtherIP_IPsec_bool">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="checkbox checkbox-sm"
									bind:checked={$form.EtherIP_IPsec_bool} />
								{m.D_SM_IPSEC__R_ETHERIP()}
							</Label>
						{/snippet}
					</Control>
				</Field>

				<button
					type="button"
					class="btn w-fit btn-sm btn-neutral not-dark:btn-soft"
					disabled={!$form.EtherIP_IPsec_bool}
					onclick={() => {
						const el = document.getElementById('etherip-detail-card');
						el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
					}}>
					{m.D_SM_IPSEC__B_DETAIL()}
				</button>
			</fieldset>

			<div class="divider my-1"></div>

			<!-- Section: IPsec Common Settings -->
			<fieldset class="fieldset">
				<legend class="fieldset-legend text-xl">{m.D_SM_IPSEC__S07()}</legend>

				<Field form={sf} name="IPsec_Secret_str">
					<Control>
						{#snippet children({ props })}
							<Label class="label">{m.D_SM_IPSEC__S_PSK()}</Label>
							<input
								{...props}
								type="text"
								class="input input-sm w-full max-w-xs"
								bind:value={$form.IPsec_Secret_str} />
						{/snippet}
					</Control>
					<FieldErrors class="text-xs text-error" />
					<p class="label">{m.D_SM_IPSEC__S_PSK2()}</p>
				</Field>
			</fieldset>

			<!-- Footer: Cancel + Save -->
			<div class="flex items-center justify-end gap-2 pt-2">
				<a href="#/" class="btn btn-sm btn-neutral not-dark:btn-soft">
					{m.D_SM_IPSEC__IDCANCEL()}
				</a>
				<Button
					type="submit"
					class="btn btn-sm btn-primary"
					loading={$submitting || saveMutation.isPending}
					disabled={$submitting || saveMutation.isPending}>
					{m.D_SM_IPSEC__IDOK()}
				</Button>
			</div>
		</form>
	</div>
</div>

<Detail hubs={hubQuery.data} show={$form.EtherIP_IPsec_bool} />
