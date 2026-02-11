<script lang="ts">
	import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';

	let { children, ...restProps }: DropdownMenuPrimitive.SubProps = $props();
</script>

<DropdownMenuPrimitive.Sub {...restProps}>
	{@render children?.()}
</DropdownMenuPrimitive.Sub>
