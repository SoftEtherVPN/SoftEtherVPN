<script lang="ts" generics="T extends Record<string, unknown>, U extends FormPathLeaves<T>">
	import { Control, Field, FieldErrors, Label } from 'formsnap';
	import type { FormPathLeaves, SuperForm } from 'sveltekit-superforms';
	import type { HTMLInputAttributes } from 'svelte/elements';

	interface Props extends Omit<HTMLInputAttributes, 'value' | 'form' | 'name' | 'class'> {
		form: SuperForm<T>;
		name: U;
		label: string;
		value: string | number | undefined;
		class?: string;
		labelClass?: string;
		errorClass?: string;
		/** Optional help text rendered below the field errors. */
		description?: string;
		descriptionClass?: string;
	}

	let {
		form,
		name,
		label,
		value = $bindable(),
		class: inputClass = 'input w-full max-w-xs input-sm',
		labelClass = 'label',
		errorClass = 'text-xs text-error',
		description,
		descriptionClass = 'label whitespace-normal',
		...rest
	}: Props = $props();
</script>

<Field {form} {name}>
	{#snippet children({ errors })}
		<Control>
			{#snippet children({ props })}
				<Label class={labelClass}>{label}</Label>
				<input
					{...props}
					{...rest}
					class={[inputClass, errors.length > 0 && 'input-error']}
					bind:value />
			{/snippet}
		</Control>
		<FieldErrors class={errorClass} />
		{#if description}
			<p class={descriptionClass}>{description}</p>
		{/if}
	{/snippet}
</Field>
