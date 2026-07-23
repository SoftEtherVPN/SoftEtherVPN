<script lang="ts">
	import Button from '$lib/components/button.svelte';
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnRpcSetGroup } from '$lib/rpc';
	import UsersRound from '@lucide/svelte/icons/users-round';
	import Cog from '@lucide/svelte/icons/cog';
	import { createMutation } from '@tanstack/svelte-query';
	import { Control, Field, Label } from 'formsnap';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import z from 'zod';
	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	const schema = z.object({
		groupName: z.string(),
		fullName: z.string().optional(),
		note: z.string().optional(),
		policyEnable: z.boolean(),
		policies: z.record(z.string(), z.union([z.number(), z.boolean()])).default({})
	});
	type FormData = z.infer<typeof schema>;

	const sf = superForm(defaults(zod4(schema)), {
		dataType: 'json',
		SPA: true,
		validators: zod4Client(schema),
		resetForm: true
	});

	const { form, enhance, constraints, reset } = sf;

	const newMutation = createMutation(() => ({
		mutationFn: (data: VpnRpcSetGroup) => rpc.CreateGroup(data)
	}));

	$effect(() => {
		if (open) reset();
	});
</script>

<Modal bind:open aria-labelledby="create-group-title">
	<h3 id="create-group-title" class="font-semibold">{m.SM_EDIT_GROUP_CAPTION_1()}</h3>
	<form use:enhance class="mt-4">
		<div class="flex">
			<UsersRound size="40" />
			<div class="ms-2 grid grow grid-cols-[auto_1fr] gap-2">
				<Field form={sf} name="groupName">
					<Control>
						{#snippet children({ props })}
							<Label class="label justify-self-end">
								{m.D_SM_EDIT_GROUP__IDC_STATIC1()}
							</Label>
							<input
								class="validator input input-sm"
								bind:value={$form.groupName}
								{...$constraints.groupName}
								{...props} />
						{/snippet}
					</Control>
				</Field>
				<Field form={sf} name="fullName">
					<Control>
						{#snippet children({ props })}
							<Label class="label justify-self-end">
								{m.D_SM_EDIT_GROUP__IDC_STATIC3()}
							</Label>
							<input
								class="input input-sm"
								bind:value={$form.fullName}
								{...$constraints.fullName}
								{...props} />
						{/snippet}
					</Control>
				</Field>
				<Field form={sf} name="note">
					<Control>
						{#snippet children({ props })}
							<Label class="label justify-self-end">
								{m.D_SM_EDIT_GROUP__IDC_STATIC4()}
							</Label>
							<input
								class="input input-sm"
								bind:value={$form.note}
								{...$constraints.note}
								{...props} />
						{/snippet}
					</Control>
				</Field>
			</div>
		</div>
		<div class="flex w-full flex-col">
			<div class="divider">{m.D_SM_EDIT_GROUP__S_POLICY_1()}</div>
			<div class="flex justify-between">
				<Cog size="32" class="self-center" />
				<Field form={sf} name="policyEnable">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									type="checkbox"
									class="checkbox checkbox-sm"
									bind:checked={$form.policyEnable}
									{...$constraints.policyEnable}
									{...props} />
								{m.D_SM_EDIT_GROUP__R_POLICY()}
							</Label>
						{/snippet}
					</Control>
				</Field>
				<button type="button" disabled={!$form.policyEnable} class="btn btn-neutral btn-sm">
					{m.D_SM_EDIT_GROUP__B_POLICY()}
				</button>
			</div>
		</div>
		<div class="modal-action">
			<Button type="submit" class="btn btn-primary btn-sm">{m.D_SM_EDIT_GROUP__IDOK()}</Button>
			<Button formmethod="dialog" formnovalidate class="btn btn-secondary btn-sm">
				{m.D_SM_EDIT_ACCESS__IDCANCEL()}
			</Button>
		</div>
	</form>
</Modal>
