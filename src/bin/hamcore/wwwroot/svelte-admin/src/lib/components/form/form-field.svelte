<script lang="ts" module>
	import type { FormPath } from 'sveltekit-superforms';
</script>

<script lang="ts" generics="T extends Record<string, unknown>, U extends FormPath<T>">
	import { Field as FieldPrimitive, type FieldProps } from 'formsnap';
	import { Field } from '$lib/components/ui/field';
	import FieldError from '../ui/field/field-error.svelte';
	import type { ComponentProps } from 'svelte';

	let {
		form,
		name,
		children: childrenProp,
		...restProps
	}: FieldProps<T, U> & ComponentProps<typeof Field> = $props();
</script>

<FieldPrimitive {form} {name}>
	{#snippet children(snippetProps)}
		<Field {...restProps}>
			{@render childrenProp?.(snippetProps)}
			<FieldError />
		</Field>
	{/snippet}
</FieldPrimitive>
