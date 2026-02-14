<script lang="ts">
	import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';

	let {
		open = $bindable(false),
		children,
		...restProps
	}: DropdownMenuPrimitive.RootProps = $props();
</script>

<DropdownMenuPrimitive.Root {...restProps}>
	{@render children?.()}
</DropdownMenuPrimitive.Root>
