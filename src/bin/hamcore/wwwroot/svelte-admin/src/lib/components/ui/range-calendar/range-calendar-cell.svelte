<script lang="ts">
	import { RangeCalendar as RangeCalendarPrimitive } from "bits-ui";
	import { cn } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: RangeCalendarPrimitive.CellProps = $props();
</script>

<RangeCalendarPrimitive.Cell
	bind:ref
	class={cn(
		"dark:[&:has([data-range-start])]:hover:bg-accent dark:[&:has([data-range-end])]:hover:bg-accent [&:has([data-range-middle])]:bg-accent dark:[&:has([data-range-middle])]:hover:bg-accent/50 [&:has([data-selected])]:bg-accent relative size-(--cell-size) p-0 text-center text-sm focus-within:z-20 data-[range-middle]:rounded-e-md [&:first-child[data-selected]_[data-bits-day]]:rounded-s-md [&:has([data-range-end])]:rounded-e-md [&:has([data-range-middle])]:rounded-none first:[&:has([data-range-middle])]:rounded-s-md last:[&:has([data-range-middle])]:rounded-e-md [&:has([data-range-start])]:rounded-s-md [&:last-child[data-selected]_[data-bits-day]]:rounded-e-md",
		className
	)}
	{...restProps}
/>
