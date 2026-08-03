<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnInternetSetting, type VpnRpcProxyType } from '$lib/rpc';
	import { serverKeys } from '$lib/rpc/query-keys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4 as zod } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, FieldErrors, Label, Fieldset } from 'formsnap';
	import Modal from '$lib/components/ui/modal.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import { ProxyMode } from '$lib/enums';

	interface Props {
		open: boolean;
	}

	let { open = $bindable(false) }: Props = $props();

	const client = useQueryClient();

	// Only fetched once the dialog is opened — nothing outside it reads the
	// setting.
	const query = createQuery(() => ({
		queryKey: serverKeys.ddnsProxy(),
		queryFn: rpc.GetDDnsInternetSetting,
		initialData: new VpnInternetSetting(),
		enabled: open
	}));

	const saveMutation = createMutation(() => ({
		mutationFn: (data: VpnInternetSetting) => rpc.SetDDnsInternetSetting(data),
		onSuccess: (result) => {
			client.setQueryData(serverKeys.ddnsProxy(), result);
			// The DDNS client re-registers through the new route, so its status
			// (and the resolved addresses) can change.
			client.invalidateQueries({ queryKey: serverKeys.ddns() });
			open = false;
		}
	}));

	// A host is only meaningful once a proxy type is picked, so requiring it is
	// conditional; `DCSetInternetSetting` stores whatever it is given.
	const schema = z
		.object({
			type: z.enum(ProxyMode),
			host: z.string(),
			port: z.coerce.number().int().min(1).max(65535),
			username: z.string(),
			password: z.string()
		})
		.refine((data) => data.type === ProxyMode.DIRECT || data.host.trim().length > 0, {
			path: ['host']
		});

	const sf = superForm(defaults(zod(schema)), {
		SPA: true,
		validators: zod(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				const direct = form.data.type === ProxyMode.DIRECT;
				await saveMutation.mutateAsync(
					new VpnInternetSetting({
						ProxyType_u32: form.data.type as unknown as VpnRpcProxyType,
						ProxyHostName_str: direct ? '' : form.data.host.trim(),
						ProxyPort_u32: direct ? 0 : form.data.port,
						ProxyUsername_str: direct ? '' : form.data.username,
						ProxyPassword_str: direct ? '' : form.data.password
					})
				);
			}
		}
	});
	const { form, errors, enhance, submitting } = sf;

	// Sync query data → form
	$effect(() => {
		const data = query.data;
		form.update(
			($form) => {
				$form.type = data.ProxyType_u32 as unknown as ProxyMode;
				$form.host = data.ProxyHostName_str;
				$form.port = data.ProxyPort_u32 || 8080;
				$form.username = data.ProxyUsername_str;
				$form.password = data.ProxyPassword_str;
				return $form;
			},
			{ taint: 'untaint-all' }
		);
	});

	const direct = $derived($form.type === ProxyMode.DIRECT);

	const types = [
		{ value: ProxyMode.DIRECT, label: m.D_SM_PROXY__R_DIRECT_TCP() },
		{ value: ProxyMode.HTTP, label: m.D_SM_PROXY__R_HTTPS() },
		{ value: ProxyMode.SOCKS4, label: m.D_SM_PROXY__R_SOCKS() },
		{ value: ProxyMode.SOCKS5, label: m.D_SM_PROXY__R_SOCKS5() }
	];
</script>

<Modal bind:open>
	<h3 class="text-lg font-bold">{m.D_SM_PROXY__CAPTION()}</h3>
	<p class="mt-1 text-sm opacity-70">{m.D_SM_PROXY__STATIC9()}</p>

	<form use:enhance>
		<Fieldset class="fieldset" form={sf} name="type">
			<legend class="fieldset-legend">{m.D_SM_PROXY__STATIC10()}</legend>
			{#each types as type (type.value)}
				<Control>
					{#snippet children({ props })}
						<Label class="label whitespace-normal text-base-content">
							<input
								{...props}
								type="radio"
								class="radio radio-sm"
								value={type.value}
								bind:group={$form.type} />
							{type.label}
						</Label>
					{/snippet}
				</Control>
			{/each}
		</Fieldset>

		{#if !direct}
			<fieldset class="fieldset">
				<!-- The field labels come from other server dialogs on purpose: the ones
				     the Manager uses here live under the `D_CM_` prefix, which
				     `convert-stb.ts` ignores as VPN Client strings. -->
				<legend class="fieldset-legend">{m.D_SM_PROXY__B_PROXY_CONFIG()}</legend>

				<Field form={sf} name="host">
					<Control>
						{#snippet children({ props })}
							<Label class="label whitespace-normal">{m.D_SM_EDIT_SETTING__STATIC5()}</Label>
							<input
								{...props}
								type="text"
								class="input w-full"
								class:input-error={$errors.host}
								bind:value={$form.host} />
						{/snippet}
					</Control>
					<FieldErrors class="label whitespace-normal text-error" />
				</Field>

				<Field form={sf} name="port">
					<Control>
						{#snippet children({ props })}
							<Label class="label whitespace-normal">{m.D_SM_EDIT_SETTING__STATIC6()}</Label>
							<input
								{...props}
								type="number"
								min="1"
								max="65535"
								class="input w-full"
								class:input-error={$errors.port}
								bind:value={$form.port} />
						{/snippet}
					</Control>
					<FieldErrors class="label whitespace-normal text-error" />
				</Field>

				<Field form={sf} name="username">
					<Control>
						{#snippet children({ props })}
							<Label class="label whitespace-normal">{m.D_SM_EDIT_USER__IDC_STATIC1()}</Label>
							<input {...props} type="text" class="input w-full" bind:value={$form.username} />
						{/snippet}
					</Control>
				</Field>

				<Field form={sf} name="password">
					<Control>
						{#snippet children({ props })}
							<Label class="label whitespace-normal">{m.D_SM_EDIT_SETTING__S_PASSWORD()}</Label>
							<input
								{...props}
								type="password"
								autocomplete="off"
								class="input w-full"
								bind:value={$form.password} />
						{/snippet}
					</Control>
				</Field>
			</fieldset>
		{/if}

		{#if saveMutation.isError}
			<div role="alert" class="mt-2 alert alert-soft alert-error">
				<span>{saveMutation.error.message}</span>
			</div>
		{/if}

		<div class="modal-action">
			<Button
				type="submit"
				class="btn btn-primary btn-sm"
				loading={$submitting || saveMutation.isPending}
				disabled={$submitting || saveMutation.isPending}>
				{m.D_SM_PROXY__IDOK()}
			</Button>
			<button class="btn btn-outline btn-sm" formmethod="dialog" formnovalidate>
				{m.D_SM_PROXY__IDCANCEL()}
			</button>
		</div>
	</form>
</Modal>
