<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { ModeWatcher } from 'mode-watcher';
	import {
		MutationCache,
		QueryCache,
		QueryClient,
		QueryClientProvider
	} from '@tanstack/svelte-query';
	import { SvelteQueryDevtools } from '@tanstack/svelte-query-devtools';
	import { LanguageSwitcher } from '$lib/components/ui/language-switcher';
	import {
		getLocale,
		setLocale,
		type Locale,
		locales as availableLocales,
		isLocale
	} from '$lib/paraglide/runtime';
	import { m } from '$lib/paraglide/messages';
	import {
		Dialog,
		DialogClose,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader
	} from '$lib/components/ui/dialog';
	import { buttonVariants } from '$lib/components/ui/button';
	import { JsonRpcException } from '$lib/rpc';

	let { children } = $props();

	let errorCode = $state('');
	let errorOpen = $state(false);

	const queryClient = new QueryClient({
		queryCache: new QueryCache({
			onError: (error, query) => {
				if (error instanceof JsonRpcException) {
					errorCode = error.Error.message;
					errorOpen = true;
				}
			}
		}),
		mutationCache: new MutationCache({
			onError: (error) => {
				if (error instanceof JsonRpcException) {
					errorCode = error.Error.message;
					errorOpen = true;
				}
			}
		})
	});

	const languages = availableLocales.map((code) => ({
		code,
		label: m.LANGSTR(undefined, { locale: code })
	}));

	let currentLang = $derived(getLocale());
</script>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>

<ModeWatcher />
<LanguageSwitcher
	{languages}
	bind:value={currentLang}
	onChange={(code) => isLocale(code) && setLocale(code)}
/>
<QueryClientProvider client={queryClient}>
	{@render children()}
	<SvelteQueryDevtools />
</QueryClientProvider>

<Dialog bind:open={errorOpen}>
	<DialogContent>
		<DialogHeader>
			<DialogDescription>{errorCode}</DialogDescription>
		</DialogHeader>
		<DialogFooter>
			<DialogClose class={buttonVariants({ variant: 'outline' })}>
				{m.D_NM_OPTION__IDOK()}
			</DialogClose>
		</DialogFooter>
	</DialogContent>
</Dialog>
