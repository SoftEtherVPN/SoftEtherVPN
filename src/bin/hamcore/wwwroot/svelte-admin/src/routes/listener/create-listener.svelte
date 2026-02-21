<script lang="ts">
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import { dashboardKey } from '$lib/queryKeys';
	import { rpc, VpnRpcListener } from '$lib/rpc';
	import InfoIcon from '@lucide/svelte/icons/info';
	import { createMutation, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4 as zod } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, FieldErrors, Label } from 'formsnap';
	import Button from '$lib/components/button.svelte';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	const client = useQueryClient();
	const createListener = createMutation(() => ({
		mutationFn: rpc.CreateListener,
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: [dashboardKey, 'listener'] });
			open = false;
		}
	}));

	const schema = z.object({ port: z.coerce.number().int().min(1).max(65535) });

	const sf = superForm(defaults(zod(schema)), {
		SPA: true,
		validators: zod(schema),
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await createListener.mutateAsync(
					new VpnRpcListener({ Port_u32: form.data['port'], Enable_bool: true })
				);
			}
		},
		onError(err) {
			console.error(err.result.error);
		}
	});

	const { form, errors, enhance, reset } = sf;

	$effect(() => {
		if (open) {
			reset();
		}
	});
</script>

<Modal bind:open aria-labelledby="create-listener-title" aria-describedby="create-listener-desc">
	<h3 id="create-listener-title" class="font-semibold">{m.D_SM_CREATE_LISTENER__CAPTION()}</h3>
	<p id="create-listener-desc" class="text-sm">{m.D_SM_CREATE_LISTENER__STATIC1()}</p>

	<form use:enhance>
		<div class="my-6 flex w-full flex-col items-center justify-center">
			<Field form={sf} name="port">
				<Control>
					{#snippet children({ props })}
						<Label class="validator input w-max">
							<span class="label">{m.D_SM_CREATE_LISTENER__STATIC3()}</span>
							<!-- svelte-ignore a11y_autofocus -->
							<input
								{...props}
								autofocus
								class="w-24"
								class:input-error={$errors['port']}
								type="number"
								bind:value={$form.port} />
							<span class="label">{m.D_SM_CREATE_LISTENER__STATIC4()}</span>
						</Label>
					{/snippet}
				</Control>
				<FieldErrors class="validator-hint" />
			</Field>
		</div>

		<div role="alert" class="alert alert-info">
			<InfoIcon />
			<span>{m.D_SM_CREATE_LISTENER__STATIC2()}</span>
		</div>

		<div class="modal-action">
			<Button
				class="btn"
				type="submit"
				loading={createListener.isPending}
				disabled={createListener.isPending}>
				{m.D_SM_CREATE_LISTENER__IDOK()}
			</Button>
			<button class="btn btn-outline" formmethod="dialog" formnovalidate>
				{m.D_SM_CREATE_LISTENER__IDCANCEL()}
			</button>
		</div>
	</form>
</Modal>
