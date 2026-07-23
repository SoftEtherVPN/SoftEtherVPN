<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		title: string;
		description?: string;
		icon?: Snippet;
		actions?: Snippet;
	}

	let { title, description, icon, actions }: Props = $props();
</script>

<div class="mb-4 flex flex-wrap items-start justify-between gap-4 max-sm:ms-2">
	<div class="flex items-start gap-3">
		{#if icon}
			<span class="grid size-11 shrink-0 place-items-center rounded-box bg-primary/10 text-primary">
				{@render icon()}
			</span>
		{/if}
		<div class="flex flex-col gap-1">
			<h1 class="text-2xl leading-tight font-bold">{title}</h1>
			{#if description}
				<p class="max-w-prose text-sm opacity-70">{description}</p>
			{/if}
		</div>
	</div>
	{#if actions}
		<div class="flex flex-wrap items-center gap-2">
			{@render actions()}
		</div>
	{/if}
</div>
