<script lang="ts">
	import { createQuery } from '@tanstack/svelte-query';
	import type { LayoutProps } from './$types';
	import { rpc, VpnRpcCreateHub } from '$lib/rpc';
	import { m } from '$lib/paraglide/messages';
	import { resolve } from '$app/paths';

	let { params, children }: LayoutProps = $props();

	const hub = createQuery(() => ({
		queryKey: ['hub', params.name],
		queryFn({ queryKey }) {
			return rpc.GetHub(new VpnRpcCreateHub({ HubName_str: queryKey[1] }));
		}
	}));
</script>

{#if hub.isLoading}
	<div class="mt-8 h-[70vh] w-full skeleton"></div>
{:else}
	<div class="mt-8 flex gap-4">
		<ul class="menu rounded-box bg-base-300">
			<li>
				<h2 class="menu-title">{m.D_SM_HUB__STATIC1()}</h2>
				<ul>
					<li>
						<a
							href={resolve('/hub/[name]/users', params)}
							class="tooltip tooltip-accent"
							data-tip={m.D_SM_HUB__S_USER()}>
							{m.D_SM_HUB__B_USER()}
						</a>
					</li>
					<li>
						<a
							href={resolve('/hub/[name]/groups', params)}
							class="tooltip tooltip-accent"
							data-tip={m.D_SM_HUB__S_GROUP()}>
							{m.D_SM_HUB__B_GROUP()}
						</a>
					</li>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_ACCESS()}>
							{m.D_SM_HUB__B_ACCESS()}
						</a>
					</li>
				</ul>
			</li>
			<li>
				<h2 class="menu-title">{m.D_SM_HUB__STATIC2()}</h2>
				<ul>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_PROPERTY()}>
							{m.D_SM_HUB__B_PROPERTY()}
						</a>
					</li>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_RADIUS()}>
							{m.D_SM_HUB__B_RADIUS()}
						</a>
					</li>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_LINK()}>
							{m.D_SM_HUB__B_LINK()}
						</a>
					</li>
				</ul>
			</li>
			<li>
				<h2 class="menu-title">{m.D_SM_HUB__STATIC4()}</h2>
				<ul>
					<li>
						<a
							class="tooltip tooltip-accent"
							href={resolve('/hub/[name]/log-setting', params)}
							data-tip={m.D_SM_HUB__S_LOG()}>
							{m.D_SM_HUB__B_LOG()}
						</a>
					</li>
					<li>
						<a
							class="tooltip tooltip-accent"
							href={resolve('/hub/[name]/log-list', params)}
							data-tip={m.D_SM_HUB__S_LOG()}>
							{m.D_SM_HUB__B_LOG_FILE()}
						</a>
					</li>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_CA()}>
							{m.D_SM_HUB__B_CA()}
						</a>
					</li>
					<li>
						<a class="tooltip tooltip-accent" data-tip={m.D_SM_HUB__S_CA()}>
							{m.D_SM_HUB__B_CRL()}
						</a>
					</li>
					<li>
						<a class="tooltip max-w-3xs tooltip-accent" data-tip={m.D_SM_HUB__S_SNAT()}>
							{m.D_SM_HUB__B_SNAT()}
						</a>
					</li>
				</ul>
			</li>
			<li>
				<h2 class="menu-title">{m.D_SM_HUB__STATIC5()}</h2>
				<ul>
					<li>
						<a>{m.D_SM_HUB__B_SESSION()}</a>
					</li>
				</ul>
			</li>
		</ul>
		<div class="grow rounded-box bg-base-300">
			{@render children()}
		</div>
	</div>
{/if}
