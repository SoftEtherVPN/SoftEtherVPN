<script lang="ts">
	import {
		getLocale,
		locales,
		setLocale,
		type Locale,
		getTextDirection
	} from '$lib/paraglide/runtime';
	import { m } from '$lib/paraglide/messages';
	import ThemeSwitcher from '$lib/components/theme-switcher.svelte';
	import House from '@lucide/svelte/icons/house';
	import Globe from '@lucide/svelte/icons/globe';
	import { onMount } from 'svelte';

	const languages: { code: Locale; flag: string }[] = [
		{ code: 'en', flag: '🇬🇧' },
		{ code: 'id', flag: '🇮🇩' },
		{ code: 'ja', flag: '🇯🇵' },
		{ code: 'ko', flag: '🇰🇷' },
		{ code: 'pt_br', flag: '🇧🇷' },
		{ code: 'ru', flag: '🇷🇺' },
		{ code: 'tr', flag: '🇹🇷' },
		{ code: 'tw', flag: '🇹🇼' },
		{ code: 'cn', flag: '🇨🇳' }
	];

	let currentLang: Locale = $state(getLocale());
	let selectedLang: (typeof languages)[number] = $derived(
		languages.find((l) => l.code == currentLang) ?? { code: currentLang, flag: '' }
	);

	onMount(() => {
		document.documentElement.lang = currentLang;
		document.documentElement.dir = getTextDirection(currentLang);
	});
</script>

<div class="navbar mt-6 rounded-xl bg-base-200 shadow-xl">
	<!-- Left: Home button -->
	<div class="navbar-start">
		<a href="#/" class="btn gap-2 text-xl font-bold btn-ghost">
			<House size={20} />
		</a>
	</div>

	<!-- Center: App title -->
	<div class="navbar-center hidden md:flex">
		<span class="text-base font-semibold tracking-wide opacity-60">SoftEther VPN Admin Panel</span>
	</div>

	<!-- Right: Language + Theme -->
	<div class="navbar-end gap-1">
		<!-- Language dropdown -->
		<div class="dropdown dropdown-end">
			<div tabindex="0" role="button" class="btn gap-1 btn-ghost btn-sm">
				<Globe size={16} />
				<span class="hidden sm:inline">
					{selectedLang.flag}
					{selectedLang.code.toUpperCase() ?? ''}
				</span>
				<span class="sm:hidden">{selectedLang.flag}</span>
				<svg
					class="h-3 w-3 opacity-60"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M19 9l-7 7-7-7" />
				</svg>
			</div>
			<ul
				class="dropdown-content menu z-10 w-52 rounded-box border border-base-300 bg-base-100 p-2 shadow-lg">
				{#each locales as code}
					{@const lang = languages.find((l) => l.code == code) ?? { code, flag: '' }}
					<li>
						<button
							class={selectedLang.code === lang.code ? 'active' : ''}
							onclick={() => setLocale(lang.code)}>
							<span>{lang.flag}</span>
							<span>{m.LANGSTR(undefined, { locale: lang.code })}</span>
						</button>
					</li>
				{/each}
			</ul>
		</div>

		<ThemeSwitcher />
	</div>
</div>
