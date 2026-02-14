<script lang="ts">
	import { cn } from "$lib/utils.js";
	import type { ComponentProps } from "svelte";
	import { Separator } from "$lib/components/ui/separator/index.js";

	let {
		ref = $bindable(null),
		class: className,
		orientation = "vertical",
		...restProps
	}: ComponentProps<typeof Separator> = $props();
</script>

<Separator
	bind:ref
	data-slot="button-group-separator"
	{orientation}
	class={cn("bg-input relative !m-0 self-stretch data-[orientation=vertical]:h-auto", className)}
	{...restProps}
/>
