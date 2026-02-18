<script lang="ts">
	import { Label } from 'formsnap';
	import type { ComponentProps } from 'svelte';
	import { FieldLabel } from '../ui/field';

	let { children: childrenProp, ...restProps }: ComponentProps<typeof Label> = $props();
</script>

<Label {...restProps}>
	{#snippet child({ props })}
		<FieldLabel {...props}>
			{@render childrenProp?.()}
		</FieldLabel>
	{/snippet}
</Label>
