<script lang="ts">
	import GripVerticalIcon from "@lucide/svelte/icons/grip-vertical";
	import * as ResizablePrimitive from "paneforge";
	import { cn, type WithoutChildrenOrChild } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		withHandle = false,
		...restProps
	}: WithoutChildrenOrChild<ResizablePrimitive.PaneResizerProps> & {
		withHandle?: boolean;
	} = $props();
</script>

<ResizablePrimitive.PaneResizer
	bind:ref
	data-slot="resizable-handle"
	class={cn(
		"bg-border focus-visible:ring-ring relative flex w-px items-center justify-center after:absolute after:inset-y-0 after:start-1/2 after:w-1 after:-translate-x-1/2 focus-visible:ring-1 focus-visible:ring-offset-1 focus-visible:outline-hidden data-[direction=vertical]:h-px data-[direction=vertical]:w-full data-[direction=vertical]:after:start-0 data-[direction=vertical]:after:h-1 data-[direction=vertical]:after:w-full data-[direction=vertical]:after:translate-x-0 data-[direction=vertical]:after:-translate-y-1/2 [&[data-direction=vertical]>div]:rotate-90",
		className
	)}
	{...restProps}
>
	{#if withHandle}
		<div class="bg-border z-10 flex h-4 w-3 items-center justify-center rounded-xs border">
			<GripVerticalIcon class="size-2.5" />
		</div>
	{/if}
</ResizablePrimitive.PaneResizer>
