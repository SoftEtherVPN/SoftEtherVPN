<script lang="ts">
	import './layout.css';
	import {
		MutationCache,
		QueryCache,
		QueryClient,
		QueryClientProvider
	} from '@tanstack/svelte-query';
	import { SvelteQueryDevtools } from '@tanstack/svelte-query-devtools';
	import { JsonRpcException } from '$lib/rpc';
	import Header from './header.svelte';
	import ConfirmDialog from '$lib/components/confirm-dialog.svelte';
	import url from '$pencore/VPNSvr.ico';
	import Modal from '$lib/components/modal.svelte';
	import { m } from '$lib/paraglide/messages';
	import Button from '$lib/components/button.svelte';
	import { errorMessages } from '$lib/err';
	import InfoIcon from '@lucide/svelte/icons/info';
	import { getLocale, getTextDirection } from '$lib/paraglide/runtime';

	let { children } = $props();

	// Keep the document language and writing direction (LTR/RTL) in sync with the
	// active locale for the whole app.
	$effect(() => {
		const locale = getLocale();
		document.documentElement.lang = locale;
		document.documentElement.dir = getTextDirection(locale);
	});

	let errorCode = $state(0);
	let errorOpen = $state(false);

	const queryClient = new QueryClient({
		queryCache: new QueryCache({
			onError: (error) => {
				if (error instanceof JsonRpcException) {
					errorCode = error.Error.code;
					errorOpen = true;
				}
			}
		}),
		mutationCache: new MutationCache({
			onError: (error) => {
				if (error instanceof JsonRpcException) {
					errorCode = error.Error.code;
					errorOpen = true;
				}
			}
		})
	});
</script>

<svelte:head>
	<title>{m.PRODUCT_NAME_VPN_SMGR()}</title>
	<link rel="icon" href={url} />
</svelte:head>

<QueryClientProvider client={queryClient}>
	<div class="container mx-auto pb-8">
		<Header />
		{@render children()}
	</div>
	<ConfirmDialog />
	<SvelteQueryDevtools />
</QueryClientProvider>

<Modal
	id="error-alert"
	role="alertdialog"
	aria-labelledby="error-alert-title"
	aria-describedby="error-alert-desc"
	bind:open={errorOpen}>
	<div class="flex gap-3">
		<InfoIcon size={20} class="mt-0.5 shrink-0 text-error" />
		<div class="flex flex-col gap-1.5">
			<p id="error-alert-title" class="font-semibold">{m.PRODUCT_NAME_VPN_SMGR()}</p>
			<p id="error-alert-desc" class="text-sm opacity-75">{errorMessages(errorCode)}</p>
		</div>
	</div>
	<div class="modal-action mt-4">
		<form method="dialog">
			<Button class="btn btn-error btn-sm">
				{m.D_NM_OPTION__IDOK()}
			</Button>
		</form>
	</div>
</Modal>
