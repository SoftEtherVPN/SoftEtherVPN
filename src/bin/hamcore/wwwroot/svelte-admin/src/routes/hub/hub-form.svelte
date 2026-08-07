<script lang="ts">
	import { goto } from '$app/navigation';
	import Button from '$lib/components/ui/button.svelte';
	import { m } from '$lib/paraglide/messages';
	import { hubKeys, serverKeys } from '$lib/rpc/query-keys';
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
	import PageHeader from '$lib/components/ui/page-header.svelte';
	import TextField from '$lib/components/ui/text-field.svelte';
	import ServerIcon from '@lucide/svelte/icons/server';
	import { resolve } from '$app/paths';
	import SetMessage from './[name]/set-message.svelte';
	import HubAdminOption from './[name]/hub-admin-option.svelte';

	let { name }: { name?: string } = $props();
	let isEdit = $derived(name != undefined);
	let setMessageOpen = $state(false);
	let adminOpen = $state(false);

	const query = createQuery(() => ({
		queryKey: hubKeys.properties(name ?? ''),
		queryFn: () => rpc.GetHub(new VpnRpcCreateHub({ HubName_str: name })),
		enabled: isEdit
	}));

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

	const setHubMutation = createMutation(() => ({
		mutationFn: rpc.SetHub,
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
				let data = new VpnRpcCreateHub({
					HubName_str: form.data.name,
					AdminPasswordPlainText_str: form.data.password,
					NoEnum_bool: form.data.noEnum,
					Online_bool: form.data.online,
					MaxSession_u32: form.data.maxSession,
					HubType_u32: form.data.type
				});
				await (isEdit ? setHubMutation.mutateAsync(data) : createHubMutation.mutateAsync(data));
				await goto(resolve('/hub/[name]', { name: data.HubName_str }));
			}
		}
	});
	const { form, enhance, submitting, reset } = sf;

	$effect(() => {
		if (!name || !query.isSuccess || !query.data) return;
		reset({
			data: {
				name: query.data.HubName_str,
				maxSession: query.data.MaxSession_u32,
				noEnum: query.data.NoEnum_bool,
				online: query.data.Online_bool,
				type: query.data.HubType_u32
			}
		});
	});
</script>

<div class="p-4">
	<PageHeader title={isEdit ? m.CM_EDIT_HUB_2({ input0: name! }) : m.CM_EDIT_HUB_1()}>
		{#snippet icon()}
			<ServerIcon size={22} />
		{/snippet}
	</PageHeader>
	{#if isEdit && query.isLoading}
		<div class="h-40 w-full skeleton"></div>
		<div class="h-64 w-full skeleton"></div>
	{:else}
		<form use:enhance>
			<TextField
				form={sf}
				name="name"
				label={m.D_SM_EDIT_HUB__STATIC1()}
				disabled={isEdit}
				type="text"
				bind:value={$form.name} />
			<div class="lg:grid lg:grid-cols-2 lg:gap-4">
				<div>
					<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
						<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC2()}</legend>
						<p class="fieldset-label">{m.D_SM_EDIT_HUB__S_BOLD()}</p>

						<TextField
							form={sf}
							name="password"
							label={m.D_SM_EDIT_HUB__STATIC3()}
							type="password"
							bind:value={$form.password} />
						<TextField
							form={sf}
							name="confirm"
							label={m.D_SM_EDIT_HUB__STATIC4()}
							type="password"
							bind:value={$form.confirm} />
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
					<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
						<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC7()}</legend>
						<p class="fieldset-label">{m.D_SM_EDIT_HUB__STATIC8()}</p>
						<Field form={sf} name="online">
							<div class="mt-2 flex gap-5">
								<Control>
									{#snippet children({ props })}
										<Label class="label">
											<input
												{...props}
												type="radio"
												class="radio radio-primary"
												bind:group={$form.online}
												value={true} />
											{m.D_SM_EDIT_HUB__R_ONLINE()}
										</Label>
									{/snippet}
								</Control>
								<Control>
									{#snippet children({ props })}
										<Label class="label">
											<input
												{...props}
												type="radio"
												class="radio radio-primary"
												bind:group={$form.online}
												value={false} />
											{m.D_SM_EDIT_HUB__R_OFFLINE()}
										</Label>
									{/snippet}
								</Control>
							</div>
						</Field>
					</fieldset>
					<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
						<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC5()}</legend>
						<Field form={sf} name="maxSession">
							<Control>
								{#snippet children({ props })}
									<Label class="lg:input w-fit">
										<span class="label">{m.D_SM_EDIT_HUB__S_MAX_SESSION_1()}</span>
										<input {...props} class="not-lg:input not-lg:my-1 lg:w-10" type="number" bind:value={$form.maxSession} />
										<span class="label">{m.D_SM_EDIT_HUB__S_MAX_SESSION_2()}</span>
									</Label>
								{/snippet}
							</Control>
						</Field>
						<p class="fieldset-label">{m.D_SM_EDIT_HUB__STATIC6()}</p>
						{#if isEdit}
							<hr class="my-2" />
							<p>{m.D_SM_EDIT_HUB__STATIC10()}</p>
							<div class="flex justify-end">
								<button type="button" class="btn btn-neutral btn-sm">
									{m.D_SM_EDIT_HUB__B_EXTOPTION()}
								</button>
							</div>
						{/if}
					</fieldset>
				</div>
				<div>
					<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
						<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__STATIC9()}</legend>
						<p class="fieldset-label">
							{isStatic ? m.CM_EDIT_HUB_STANDALONE() : m.CM_EDIT_HUB_TYPE_FIXED()}
						</p>
						<Field form={sf} name="type">
							<div class="mt-2 flex gap-5">
								<Control>
									{#snippet children({ props })}
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
									{/snippet}
								</Control>
								<Control>
									{#snippet children({ props })}
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
									{/snippet}
								</Control>
							</div>
						</Field>
					</fieldset>
					{#if isEdit}
						<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
							<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__S_AO_1()}</legend>
							<p class="fieldset-label">
								{m.D_SM_EDIT_HUB__S_AO_3()}
							</p>
							<div class="flex justify-end">
								<button
									type="button"
									class="btn btn-neutral btn-sm"
									onclick={() => (adminOpen = true)}>
									{m.D_SM_EDIT_HUB__B_ADMINOPTION()}
								</button>
							</div>
						</fieldset>
						<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
							<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__S_ACL_3()}</legend>
							<p class="fieldset-label">
								{m.D_SM_EDIT_HUB__S_ACL()}
							</p>
							<div class="flex justify-end">
								<button type="button" class="btn btn-neutral btn-sm">
									{m.D_SM_EDIT_HUB__B_ACL()}
								</button>
							</div>
						</fieldset>
						<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
							<legend class="fieldset-legend">{m.D_SM_EDIT_HUB__S_MSG_1()}</legend>
							<p class="fieldset-label">
								{m.D_SM_EDIT_HUB__S_MSG_2()}
							</p>
							<div class="flex justify-end">
								<button
									type="button"
									onclick={() => (setMessageOpen = true)}
									class="btn btn-neutral btn-sm">
									{m.D_SM_EDIT_HUB__B_MSG()}
								</button>
							</div>
						</fieldset>
					{/if}
				</div>
			</div>
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
	{/if}
</div>

{#if isEdit}
	<SetMessage hub={name!} bind:open={setMessageOpen} />
	<HubAdminOption hub={name!} bind:open={adminOpen} />
{/if}
