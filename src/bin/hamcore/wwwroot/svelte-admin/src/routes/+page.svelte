<script lang="ts">
	import Hub from './hub/hub.svelte';
	import Listeners from './listeners.svelte';
</script>

<div class="grid grid-cols-3 gap-4">
	<div class="col-span-3"><Hub /></div>
	<div>
		<Listeners />
	</div>
</div>
