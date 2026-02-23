<script lang="ts">
	import Button from '$lib/components/button.svelte';
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnEtherIpId, VpnRpcEnumHubItem } from '$lib/rpc';
	import { createMutation, useQueryClient } from '@tanstack/svelte-query';
	import { Control, Field, FieldErrors, Label } from 'formsnap';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4Client, zod4 } from 'sveltekit-superforms/adapters';
	import z from 'zod';

	interface Props {
		open: boolean;
		hubs: VpnRpcEnumHubItem[];
	}

	let { open = $bindable(), hubs }: Props = $props();

	const client = useQueryClient();

	const addSchema = z.object({
		Id_str: z.string().min(1),
		HubName_str: z.string().min(1),
		UserName_str: z.string().min(1),
		Password_str: z.string().min(1)
	});

	const addMutation = createMutation(() => ({
		mutationFn: (data: VpnEtherIpId) => rpc.AddEtherIpId(data),
		onSuccess: async () => {
			open = false;
			await client.invalidateQueries({ queryKey: ['ipsec', 'detail'] });
		}
	}));

	const addSf = superForm(defaults(zod4(addSchema)), {
		SPA: true,
		validators: zod4Client(addSchema),
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await addMutation.mutateAsync(
					new VpnEtherIpId({
						Id_str: form.data.Id_str,
						HubName_str: form.data.HubName_str,
						UserName_str: form.data.UserName_str,
						Password_str: form.data.Password_str
					})
				);
			}
		}
	});

	const { form: addForm, enhance, reset } = addSf;

	// Reset add form when modal closes
	$effect(() => {
		if (!open) {
			reset();
		}
	});

	// Pre-select first hub when hubs load and none is selected
	$effect(() => {
		if (hubs && hubs.length > 0 && !$addForm.HubName_str) {
			$addForm.HubName_str = hubs[0]!.HubName_str;
		}
	});
</script>

<!-- EtherIP Add Modal (outside main form) -->
<Modal bind:open>
	<h3 class="font-semibold">{m.D_SM_ETHERIP_ID__CAPTION()}</h3>
	<p class="mt-1 text-sm opacity-70">{m.D_SM_ETHERIP_ID__S01()}</p>

	<form use:enhance class="mt-4 flex flex-col gap-4">
		<!-- Phase 1 ID -->
		<Field form={addSf} name="Id_str">
			<div class="flex flex-col gap-1">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_ETHERIP_ID__S02()}</Label>
						<input
							{...props}
							type="text"
							class="validator input w-full"
							bind:value={$addForm.Id_str} />
					{/snippet}
				</Control>
				<FieldErrors class="validator-hint text-xs" />
			</div>
			<p class="text-sm opacity-60">{m.D_SM_ETHERIP_ID__S07()}</p>
		</Field>

		<!-- Virtual Hub select -->
		<Field form={addSf} name="HubName_str">
			<div class="flex flex-col gap-1">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_ETHERIP_ID__S03()}</Label>
						<select {...props} class="validator select w-full" bind:value={$addForm.HubName_str}>
							{#each hubs as hub (hub.HubName_str)}
								<option value={hub.HubName_str}>{hub.HubName_str}</option>
							{/each}
						</select>
					{/snippet}
				</Control>
				<FieldErrors class="validator-hint text-xs" />
			</div>
		</Field>

		<!-- Username -->
		<Field form={addSf} name="UserName_str">
			<div class="flex flex-col gap-1">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_ETHERIP_ID__S04()}</Label>
						<input
							{...props}
							type="text"
							class="validator input w-full"
							bind:value={$addForm.UserName_str} />
					{/snippet}
				</Control>
				<FieldErrors class="validator-hint text-xs" />
			</div>
		</Field>

		<!-- Password -->
		<Field form={addSf} name="Password_str">
			<div class="flex flex-col gap-1">
				<Control>
					{#snippet children({ props })}
						<Label class="label">{m.D_SM_ETHERIP_ID__S05()}</Label>
						<input
							{...props}
							type="password"
							class="validator input w-full"
							bind:value={$addForm.Password_str} />
					{/snippet}
				</Control>
				<FieldErrors class="validator-hint text-error" />
			</div>
		</Field>

		<p class="text-sm opacity-60">{m.D_SM_ETHERIP_ID__S06()}</p>

		<div class="card-actions justify-end gap-2">
			<button
				type="button"
				class="btn btn-neutral not-dark:btn-soft"
				onclick={() => (open = false)}>
				{m.D_SM_ETHERIP_ID__IDCANCEL()}
			</button>
			<Button
				type="submit"
				class="btn btn-primary"
				loading={addMutation.isPending}
				disabled={addMutation.isPending}>
				{m.D_SM_ETHERIP_ID__IDOK()}
			</Button>
		</div>
	</form>
</Modal>
