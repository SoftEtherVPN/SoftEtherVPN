<script lang="ts">
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { LanguageSwitcher } from '$lib/components/ui/language-switcher';
	import SunIcon from '@lucide/svelte/icons/sun';
	import MoonIcon from '@lucide/svelte/icons/moon';
	import { m } from '$lib/paraglide/messages';
	import {
		getLocale,
		isLocale,
		setLocale,
		locales as availableLocales
	} from '$lib/paraglide/runtime';
	import { buttonVariants } from '$lib/components/ui/button';
	import { resetMode, setMode } from 'mode-watcher';
	import url from '../../../../../../PenCore/VPNSvr.ico';

	const languages = availableLocales.map((code) => ({
		code,
		label: m.LANGSTR(undefined, { locale: code })
	}));

	let currentLang = $derived(getLocale());
</script>

<div class="flex justify-between pt-4 pb-8">
	<div class="flex items-center gap-2">
		<img class="inline size-8" src={url} alt="Logo" />
		<p class="text-lg font-bold">SoftEther VPN Svelte Admin</p>
	</div>
	<div>
		<DropdownMenu.Root>
			<DropdownMenu.Trigger class={buttonVariants({ variant: 'outline', size: 'icon' })}>
				<SunIcon
					class="h-[1.2rem] w-[1.2rem] scale-100 rotate-0 transition-all! dark:scale-0 dark:-rotate-90" />
				<MoonIcon
					class="absolute h-[1.2rem] w-[1.2rem] scale-0 rotate-90 transition-all! dark:scale-100 dark:rotate-0" />
				<span class="sr-only">Toggle theme</span>
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="end">
				<DropdownMenu.Item onclick={() => setMode('light')}>Light</DropdownMenu.Item>
				<DropdownMenu.Item onclick={() => setMode('dark')}>Dark</DropdownMenu.Item>
				<DropdownMenu.Item onclick={() => resetMode()}>System</DropdownMenu.Item>
			</DropdownMenu.Content>
		</DropdownMenu.Root>
		<LanguageSwitcher
			{languages}
			bind:value={currentLang}
			onChange={(code) => isLocale(code) && setLocale(code)} />
	</div>
</div>
