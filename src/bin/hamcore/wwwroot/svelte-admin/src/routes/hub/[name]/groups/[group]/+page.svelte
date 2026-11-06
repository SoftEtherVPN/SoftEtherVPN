<script lang="ts">
	import GroupForm from '../group-form.svelte';
	import type { PageProps } from './$types';

	let { params }: PageProps = $props();
</script>

<GroupForm hub={params.name} name={params.group} />
