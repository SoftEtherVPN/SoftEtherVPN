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
	import url from '../../../../../../PenCore/VPNSvr.ico';

	let { children } = $props();

	let errorCode = $state('');
	let errorOpen = $state(false);

	const queryClient = new QueryClient({
		queryCache: new QueryCache({
			onError: (error) => {
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
</script>

<svelte:head><link rel="icon" href={url} /></svelte:head>

<QueryClientProvider client={queryClient}>
	<div class="container mx-auto">
		<Header />
		{@render children()}
	</div>
	<ConfirmDialog />
	<SvelteQueryDevtools />
</QueryClientProvider>
