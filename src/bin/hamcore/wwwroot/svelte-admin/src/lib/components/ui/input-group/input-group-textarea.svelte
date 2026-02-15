<script lang="ts">
	import { cn } from "$lib/utils.js";
	import { Textarea } from "$lib/components/ui/textarea/index.js";
	import type { ComponentProps } from "svelte";

	let {
		ref = $bindable(null),
		value = $bindable(),
		class: className,
		...props
	}: ComponentProps<typeof Textarea> = $props();
</script>

<Textarea
	bind:ref
	data-slot="input-group-control"
	class={cn(
		"flex-1 resize-none rounded-none border-0 bg-transparent py-3 shadow-none focus-visible:ring-0 dark:bg-transparent",
		className
	)}
	bind:value
	{...props}
/>
