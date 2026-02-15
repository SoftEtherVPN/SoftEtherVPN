<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLSelectAttributes } from "svelte/elements";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";

	let {
		ref = $bindable(null),
		value = $bindable(),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLSelectAttributes> = $props();
</script>

<div
	class="group/native-select relative w-fit has-[select:disabled]:opacity-50"
	data-slot="native-select-wrapper"
>
	<select
		bind:value
		bind:this={ref}
		data-slot="native-select"
		class={cn(
			"border-input placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground dark:bg-input/30 dark:hover:bg-input/50 h-9 w-full min-w-0 appearance-none rounded-md border bg-transparent px-3 py-2 pe-9 text-sm shadow-xs transition-[color,box-shadow] outline-none disabled:pointer-events-none disabled:cursor-not-allowed",
			"focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]",
			"aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",
			className
		)}
		{...restProps}
	>
		{@render children?.()}
	</select>
	<ChevronDownIcon
		class="text-muted-foreground pointer-events-none absolute end-3.5 top-1/2 size-4 -translate-y-1/2 opacity-50 select-none"
		aria-hidden="true"
		data-slot="native-select-icon"
	/>
</div>
