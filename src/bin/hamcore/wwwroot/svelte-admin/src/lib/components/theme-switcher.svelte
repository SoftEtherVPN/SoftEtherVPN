<script lang="ts">
	import { browser } from '$app/environment';
	import Moon from '@lucide/svelte/icons/moon';
	import Sun from '@lucide/svelte/icons/sun';
	import { onMount } from 'svelte';

	function getInitialValue() {
		if (browser) {
			const isDark = window.matchMedia('(prefers-color-scheme: dark)');
			return isDark.matches;
		}
		return false;
	}

	let systemDarkMode = $state(getInitialValue());
	let settedIsDarkMode = $state<boolean | undefined>(undefined);

	onMount(() => {
		const isDark = window.matchMedia('(prefers-color-scheme: dark)');
		systemDarkMode = isDark.matches;
		isDark.addEventListener('change', (ev) => (systemDarkMode = ev.matches));
	});

	$effect(() => {
		let isDarkMode = settedIsDarkMode ?? systemDarkMode;
		document.documentElement.setAttribute('data-theme', isDarkMode ? 'night' : 'corporate');
	});
</script>

<label class="btn swap btn-circle swap-rotate btn-ghost btn-sm">
	<input defaultChecked={systemDarkMode} bind:checked={settedIsDarkMode} type="checkbox" />
	<Moon class="swap-on" size={20} />
	<Sun class="swap-off" size={20} />
</label>
