<script lang="ts">
	import HubForm from '../../hub-form.svelte';
	import type { PageProps } from './$types';

	let { params }: PageProps = $props();
</script>

<HubForm name={params.name} />
