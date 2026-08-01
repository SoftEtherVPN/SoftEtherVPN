<script lang="ts">
	import { goto } from '$app/navigation';
	import Button from '$lib/components/button.svelte';
	import { m } from '$lib/paraglide/messages';
	import { hubKeys, serverKeys } from '$lib/queryKeys';
	import {
		rpc,
		VpnRpcCreateHub,
		VpnRpcHubType,
		VpnRpcServerInfo,
		VpnRpcServerType
	} from '$lib/rpc';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { Control, Field, FieldErrors, Label } from 'formsnap';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import z from 'zod';

	const serverInfo = createQuery(() => ({
		queryKey: serverKeys.info(),
		queryFn: rpc.GetServerInfo,
		initialData: new VpnRpcServerInfo()
	}));

	let isStatic = $derived(serverInfo.data.ServerType_u32 == VpnRpcServerType.Standalone);
	const client = useQueryClient();
	const createHubMutation = createMutation(() => ({
		mutationFn: rpc.CreateHub,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.all });
		}
	}));

	const schema = z
		.object({
			name: z.string().min(1),
			password: z.string().optional(),
			confirm: z.string().optional(),
			noEnum: z.boolean().default(false),
			online: z.boolean().default(true),
			maxSession: z.number().min(0).optional().default(0),
			type: z.enum(VpnRpcHubType).optional().default(0)
		})
		.refine((data) => data.password === data.confirm, {
			message: m.SM_CHANGE_PASSWORD_1(),
			path: ['confirm']
		});

	const sf = superForm(defaults(zod4(schema)), {
		SPA: true,
		validators: zod4Client(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await createHubMutation.mutateAsync(
					new VpnRpcCreateHub({
						HubName_str: form.data.name,
						AdminPasswordPlainText_str: form.data.password,
						NoEnum_bool: form.data.noEnum,
						Online_bool: form.data.online,
						MaxSession_u32: form.data.maxSession,
						HubType_u32: form.data.type
					})
				);
				await goto('#/');
			}
		}
	});
	const { form, enhance, submitting } = sf;
</script>

<div class="mx-auto max-w-md">
	<div class="my-4 ms-4">
		<h1 class="text-2xl font-bold">{m.CM_EDIT_HUB_1()}</h1>
	</div>

	<form use:enhance>
		<Field form={sf} name="name">
			<Control>
				{#snippet children({ props })}
					<Label class="label">{m.D_SM_EDIT_HUB__STATIC1()}</Label>
					<input
						{...props}
						type="text"
						class="input w-full max-w-xs input-sm"
						bind:value={$form.name} />
				{/snippet}
			</Control>
			<FieldErrors class="text-xs text-error" />
		</Field>
		<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
			<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC2()}</legend>
			<p class="fieldset-label">{m.D_SM_EDIT_HUB__S_BOLD()}</p>

			<Field form={sf} name="password">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_EDIT_HUB__STATIC3()}</Label>
						<input
							{...props}
							type="password"
							class="input w-full max-w-xs input-sm"
							bind:value={$form.password} />
					{/snippet}
				</Control>
				<FieldErrors class="text-xs text-error" />
			</Field>
			<Field form={sf} name="confirm">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_EDIT_HUB__STATIC4()}</Label>
						<input
							{...props}
							type="password"
							class="input w-full max-w-xs input-sm"
							bind:value={$form.confirm} />
					{/snippet}
				</Control>
				<FieldErrors class="text-xs text-error" />
			</Field>
			<Field form={sf} name="noEnum">
				<Control>
					{#snippet children({ props })}
						<Label class="label">
							<input
								{...props}
								type="checkbox"
								class="checkbox checkbox-primary"
								bind:checked={$form.noEnum} />
							{m.D_SM_EDIT_HUB__R_NO_ENUM()}
						</Label>
					{/snippet}
				</Control>
				<FieldErrors class="text-xs text-error" />
			</Field>
		</fieldset>
		<fieldset class="mt-4 fieldset rounded-box border border-base-300 bg-base-200 p-4">
			<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC7()}</legend>
			<p class="fieldset-label">{m.D_SM_EDIT_HUB__STATIC8()}</p>
			<Field form={sf} name="online">
				<Control>
					{#snippet children({ props })}
						<div class="mt-2 flex gap-5">
							<Label class="label">
								<input
									{...props}
									type="radio"
									class="radio radio-primary"
									bind:group={$form.online}
									value={true} />
								{m.D_SM_EDIT_HUB__R_ONLINE()}
							</Label>
							<Label class="label">
								<input
									{...props}
									type="radio"
									class="radio radio-primary"
									bind:group={$form.online}
									value={false} />
								{m.D_SM_EDIT_HUB__R_OFFLINE()}
							</Label>
						</div>
					{/snippet}
				</Control>
			</Field>
		</fieldset>
		<fieldset class="mt-4 fieldset rounded-box border border-base-300 bg-base-200 p-4">
			<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC5()}</legend>
			<Field form={sf} name="maxSession">
				<Control>
					{#snippet children({ props })}
						<Label class="input w-fit">
							<span class="label">{m.D_SM_EDIT_HUB__S_MAX_SESSION_1()}</span>
							<input {...props} class="w-10" type="number" bind:value={$form.maxSession} />
							<span class="label">{m.D_SM_EDIT_HUB__S_MAX_SESSION_2()}</span>
						</Label>
					{/snippet}
				</Control>
			</Field>
			<p class="fieldset-label">{m.D_SM_EDIT_HUB__STATIC6()}</p>
		</fieldset>
		<fieldset class="mt-4 fieldset rounded-box border border-base-300 bg-base-200 p-4">
			<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC9()}</legend>
			<p class="fieldset-label">
				{isStatic ? m.CM_EDIT_HUB_STANDALONE() : m.CM_EDIT_HUB_TYPE_FIXED()}
			</p>
			<Field form={sf} name="type">
				<Control>
					{#snippet children({ props })}
						<div class="mt-2 flex gap-5">
							<Label class="label">
								<input
									{...props}
									type="radio"
									class="radio radio-primary"
									disabled={isStatic}
									bind:group={$form.type}
									value={VpnRpcHubType.FarmStatic} />
								{m.D_SM_EDIT_HUB__R_STATIC()}
							</Label>
							<Label class="label">
								<input
									{...props}
									type="radio"
									class="radio radio-primary"
									disabled={isStatic}
									bind:group={$form.type}
									value={VpnRpcHubType.FarmDynamic} />
								{m.D_SM_EDIT_HUB__R_DYNAMIC()}
							</Label>
						</div>
					{/snippet}
				</Control>
			</Field>
		</fieldset>
		<div class="mt-2 flex justify-end gap-2">
			<a href="#/" class="btn btn-neutral btn-sm not-dark:btn-soft">
				{m.D_SM_EDIT_HUB__IDCANCEL()}
			</a>
			<Button
				type="submit"
				class="btn btn-primary btn-sm"
				loading={$submitting || createHubMutation.isPending}
				disabled={$submitting || createHubMutation.isPending}>
				{m.D_SM_EDIT_HUB__IDOK()}
			</Button>
		</div>
	</form>
</div>
