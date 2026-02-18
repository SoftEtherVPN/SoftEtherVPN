<script lang="ts">
	import { Description } from 'formsnap';
	import type { ComponentProps } from 'svelte';
	import { FieldDescription } from '../ui/field';

	let { children: childrenProp, ...restProps }: ComponentProps<typeof Description> = $props();
</script>

<Description {...restProps}>
	{#snippet child({ props })}
		<FieldDescription {...props}>
			{@render childrenProp?.()}
		</FieldDescription>
	{/snippet}
</Description>
