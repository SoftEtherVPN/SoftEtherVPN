<script lang="ts">
	import type { Writable } from 'svelte/store';
	import { m } from '$lib/paraglide/messages';
	import {
		POLICIES,
		policyLabel,
		policyDescription,
		policyUnitLabel,
		type PolicyFormData
	} from '$lib/rpc/policies';
	import ShieldIcon from '@lucide/svelte/icons/shield-check';

	// The superForm data store. It must expose the PolicyFormData fields; extra
	// fields (group/user identity, …) are ignored here.
	let { form }: { form: Writable<PolicyFormData> } = $props();
</script>

<div class="card bg-base-300 shadow">
	<div class="card-body gap-4">
		<div class="flex flex-wrap items-center justify-between gap-3">
			<h3 class="flex items-center gap-2 text-lg font-semibold">
				<ShieldIcon size={18} class="opacity-70" />
				{m.D_SM_EDIT_GROUP__S_POLICY_1()}
			</h3>
			<label class="label cursor-pointer gap-2">
				<input type="checkbox" class="toggle toggle-sm" bind:checked={$form.usePolicy} />
				{m.D_SM_EDIT_GROUP__R_POLICY()}
			</label>
		</div>

		{#if $form.usePolicy}
			<div
				class="max-h-112 divide-y divide-base-100 overflow-y-auto rounded-box border border-base-100">
				{#each POLICIES as p (p.key)}
					<div class="flex items-center justify-between gap-4 p-3">
						<div class="flex min-w-0 items-start gap-3">
							{#if p.type === 'num'}
								<input
									type="checkbox"
									class="toggle mt-0.5 shrink-0 toggle-sm"
									aria-label={policyLabel(p.index)}
									bind:checked={$form.numEnabled[p.key]} />
							{/if}
							<div class="min-w-0">
								<p class="text-sm font-medium">{policyLabel(p.index)}</p>
								<p class="text-xs opacity-60">{policyDescription(p.index)}</p>
							</div>
						</div>
						{#if p.type === 'bool'}
							<input
								type="checkbox"
								class="toggle shrink-0 toggle-sm"
								aria-label={policyLabel(p.index)}
								bind:checked={$form.boolPolicies[p.key]} />
						{:else}
							<div class="flex shrink-0 items-center gap-2">
								<input
									type="number"
									min={p.min}
									max={p.max}
									class="input w-36 tabular-nums input-sm"
									aria-label={policyLabel(p.index)}
									disabled={!$form.numEnabled[p.key]}
									bind:value={$form.numPolicies[p.key]} />
								{#if p.unit}
									<span class="w-14 text-xs opacity-60">{policyUnitLabel(p.unit)}</span>
								{/if}
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	</div>
</div>
