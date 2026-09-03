<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { rpc, VpnDDnsClientStatus, VpnRpcTest } from '$lib/rpc';
	import { errorMessages } from '$lib/rpc/errors';
	import { getDDnsKey } from '$lib/rpc/ddns-key';
	import { serverKeys } from '$lib/rpc/query-keys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4 as zod } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { Field, Control, FieldErrors, Label } from 'formsnap';
	import Modal from '$lib/components/ui/modal.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import PageHeader from '$lib/components/ui/page-header.svelte';
	import ProxyDialog from './proxy-dialog.svelte';
	import GlobeIcon from '@lucide/svelte/icons/globe';
	import InfoIcon from '@lucide/svelte/icons/info';
	import KeyRoundIcon from '@lucide/svelte/icons/key-round';
	import RotateCcwIcon from '@lucide/svelte/icons/rotate-ccw';

	/** `ERR_CONNECT_FAILED`, the one code the Manager phrases itself. */
	const ERR_CONNECT_FAILED = 1;
	const ERR_NO_ERROR = 0;

	const client = useQueryClient();

	// ── Queries ───────────────────────────────────────────────────────────────

	const ddnsQuery = createQuery(() => ({
		queryKey: serverKeys.ddns(),
		queryFn: rpc.GetDDnsClientStatus,
		initialData: new VpnDDnsClientStatus()
	}));

	// Read out of the configuration file, and it never changes on its own.
	const keyQuery = createQuery(() => ({
		queryKey: serverKeys.ddnsKey(),
		queryFn: getDDnsKey,
		staleTime: Infinity,
		retry: false
	}));

	const capsQuery = createQuery(() => ({
		queryKey: serverKeys.caps(),
		queryFn: rpc.GetCaps,
		staleTime: Infinity
	}));

	let proxyOpen = $state(false);

	const st = $derived(ddnsQuery.data);

	const proxySupported = $derived(
		capsQuery.data?.CapsList.some(
			(caps) => caps.CapsName_str === 'b_support_ddns_proxy' && caps.CapsValue_u32 !== 0
		) ?? false
	);

	// Nothing can be changed while neither address family reaches the DDNS
	// servers — same gate as `SmDDnsRefresh`.
	const reachable = $derived(st.Err_IPv4_u32 === ERR_NO_ERROR || st.Err_IPv6_u32 === ERR_NO_ERROR);

	function addressOf(error: number, address: string, unreachable: string) {
		if (error === ERR_NO_ERROR) return address;
		return error === ERR_CONNECT_FAILED ? unreachable : errorMessages(error);
	}

	const ipv4 = $derived(addressOf(st.Err_IPv4_u32, st.CurrentIPv4_str, m.SM_DDNS_IPV4_ERROR()));
	const ipv6 = $derived(addressOf(st.Err_IPv6_u32, st.CurrentIPv6_str, m.SM_DDNS_IPV6_ERROR()));

	// ── Change hostname ───────────────────────────────────────────────────────

	const changeMutation = createMutation(() => ({
		mutationFn: (name: string) =>
			rpc.ChangeDDnsClientHostname(new VpnRpcTest({ StrValue_str: name })),
		onSuccess: async (_, name) => {
			await client.invalidateQueries({ queryKey: serverKeys.ddns() });
			showHint(m.SM_DDNS_OK_TITLE(), m.SM_DDNS_OK_MSG2({ input0: name }));
		}
	}));

	// `DCChangeHostName` only rejects names over 32 characters; the rest of the
	// rule is the one the dialog states, and the DDNS server enforces.
	const schema = z.object({
		hostname: z
			.string()
			.trim()
			.regex(/^[a-z0-9-]{3,32}$/i, { message: m.ERR_134() })
	});

	const sf = superForm(defaults(zod(schema)), {
		SPA: true,
		validators: zod(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await changeMutation.mutateAsync(form.data.hostname.trim());
			}
		}
	});
	const { form, errors, enhance, submitting } = sf;

	// Sync query data → form
	$effect(() => {
		const data = ddnsQuery.data;
		form.update(
			($form) => {
				$form.hostname = data.CurrentHostName_str;
				return $form;
			},
			{ taint: 'untaint-all' }
		);
	});

	const changed = $derived($form.hostname.trim() !== st.CurrentHostName_str);

	// ── Hint dialogs ──────────────────────────────────────────────────────────

	let hintOpen = $state(false);
	let hint = $state({ title: '', body: '' });

	function showHint(title: string, body: string) {
		hint = { title, body };
		hintOpen = true;
	}

	function showHostnameHint() {
		const none = m.SM_DDNS_FQDN_EMPTY();
		showHint(
			m.SM_DDNS_OK_TITLE(),
			m.SM_DDNS_OK_MSG({
				input0: st.CurrentHostName_str,
				input1: st.DnsSuffix_str,
				input2: st.CurrentIPv4_str || none,
				input3: st.CurrentIPv6_str || none,
				input4: st.CurrentHostName_str,
				input5: st.DnsSuffix_str,
				input6: st.CurrentHostName_str,
				input7: st.DnsSuffix_str
			})
		);
	}
</script>

<div class="mx-auto mt-4 max-w-3xl">
	<PageHeader title={m.D_SM_DDNS__S_TITLE()}>
		{#snippet icon()}
			<GlobeIcon size={22} />
		{/snippet}
		{#snippet actions()}
			<span class={['badge gap-1.5 badge-soft', reachable ? 'badge-success' : 'badge-error']}>
				<span class={['status', reachable ? 'status-success' : 'status-error']}></span>
				{reachable ? st.CurrentFqdn_str || m.SM_DDNS_FQDN_EMPTY() : m.SM_DDNS_IPV4_ERROR()}
			</span>
		{/snippet}
	</PageHeader>

	<div class="card bg-base-100 shadow dark:bg-base-300">
		<div class="card-body">
			<h2 class="card-title">{m.D_SM_DDNS__S_BOLD()}</h2>
			<div class="flex flex-col gap-2 text-sm leading-relaxed whitespace-pre-line opacity-70">
				<span>{m.D_SM_DDNS__S_1()}</span>
				<span>{m.D_SM_DDNS__S_22()}</span>
				<span>{m.D_SM_DDNS__S_3()}</span>
			</div>

			<div class="mt-2 grid gap-4 md:grid-cols-2">
				<!-- Current Status -->
				<fieldset
					class="fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
					<legend class="fieldset-legend">{m.D_SM_DDNS__S_4()}</legend>

					<span class="label whitespace-normal">{m.D_SM_DDNS__S_STATUS3()}</span>
					<div class="flex flex-wrap items-center justify-between gap-2">
						<span class="font-mono text-base break-all">
							{st.CurrentFqdn_str || m.SM_DDNS_FQDN_EMPTY()}
						</span>
						<Button
							class="btn gap-1.5 btn-outline btn-xs"
							disabled={!reachable}
							onclick={showHostnameHint}>
							<InfoIcon size={14} />
							{m.D_SM_DDNS__B_HINT()}
						</Button>
					</div>

					<span class="label mt-2 whitespace-normal">{m.D_SM_DDNS__S_STATUS4()}</span>
					<span
						class={[
							'font-mono break-all',
							st.Err_IPv4_u32 !== ERR_NO_ERROR && 'font-sans text-sm text-error'
						]}>
						{ipv4}
					</span>

					<span class="label mt-2 whitespace-normal">{m.D_SM_DDNS__S_STATUS5()}</span>
					<span
						class={[
							'font-mono break-all',
							st.Err_IPv6_u32 !== ERR_NO_ERROR && 'font-sans text-sm text-error'
						]}>
						{ipv6}
					</span>

					<span class="label mt-2 whitespace-normal">{m.D_SM_DDNS__S_STATUS8()}</span>
					<div class="flex flex-wrap items-center justify-between gap-2">
						<span class="font-mono text-xs break-all">
							{keyQuery.data ?? (keyQuery.isPending ? '' : m.SM_DDNS_KEY_ERR())}
						</span>
						<Button
							class="btn gap-1.5 btn-outline btn-xs"
							disabled={!keyQuery.data}
							onclick={() =>
								showHint(
									m.SM_DDNS_KEY_TITLE(),
									m.SM_DDNS_KEY_MSG({ input0: keyQuery.data ?? '' })
								)}>
							<KeyRoundIcon size={14} />
							{m.D_SM_DDNS__B_HINT2()}
						</Button>
					</div>
				</fieldset>

				<!-- Modify the Settings -->
				<fieldset
					class="fieldset rounded-box border border-base-300 bg-base-200 p-4 dark:border-base-100">
					<legend class="fieldset-legend">{m.D_SM_DDNS__S_5()}</legend>

					<form use:enhance class="contents">
						<Field form={sf} name="hostname">
							<Control>
								{#snippet children({ props })}
									<Label class="label whitespace-normal">{m.D_SM_DDNS__S_STATUS6()}</Label>
									<div class="join w-full">
										<input
											{...props}
											type="text"
											class="input join-item w-full font-mono"
											class:input-error={$errors.hostname}
											maxlength="32"
											autocapitalize="none"
											autocomplete="off"
											spellcheck="false"
											disabled={!reachable}
											bind:value={$form.hostname} />
										<span class="btn pointer-events-none join-item font-mono btn-secondary">
											{st.DnsSuffix_str}
										</span>
									</div>
								{/snippet}
							</Control>
							<FieldErrors class="label whitespace-normal text-error" />
						</Field>
						<p class="label whitespace-pre-line">{m.D_SM_DDNS__S_STATUS7()}</p>

						{#if changeMutation.isError}
							<div role="alert" class="alert alert-soft alert-error">
								<span>{changeMutation.error.message}</span>
							</div>
						{/if}

						<div class="mt-auto flex flex-wrap justify-end gap-2 pt-2">
							<Button
								type="submit"
								class="btn grow btn-primary btn-sm"
								disabled={!reachable || !changed}
								loading={$submitting || changeMutation.isPending}>
								{m.D_SM_DDNS__IDOK()}
							</Button>
							<Button
								type="button"
								class="btn gap-1.5 btn-sm"
								disabled={!reachable || !changed}
								onclick={() => ($form.hostname = st.CurrentHostName_str)}>
								<RotateCcwIcon size={14} />
								{m.D_SM_DDNS__B_RESTORE()}
							</Button>
						</div>
					</form>
				</fieldset>
			</div>

			<div role="alert" class="mt-2 alert alert-soft alert-info">
				<InfoIcon size={18} class="shrink-0" />
				<span class="whitespace-pre-line">{m.D_SM_DDNS__S_2()}</span>
			</div>

			<div class="card-actions justify-end">
				<button
					class="btn me-auto btn-neutral btn-sm not-dark:btn-soft"
					onclick={() => showHint(m.SM_DISABLE_DDNS_HINT_CAPTION(), m.SM_DISABLE_DDNS_HINT())}>
					{m.D_SM_DDNS__B_DISABLE()}
				</button>
				{#if proxySupported}
					<button
						class="btn btn-neutral btn-sm not-dark:btn-soft"
						onclick={() => (proxyOpen = true)}>
						{m.D_SM_DDNS__B_PROXY()}
					</button>
				{/if}
				<a href="#/" class="btn btn-primary btn-sm">{m.D_SM_DDNS__IDCANCEL()}</a>
			</div>
		</div>
	</div>
</div>

<Modal bind:open={hintOpen}>
	<h3 class="text-lg font-bold">{hint.title}</h3>
	<p class="mt-2 text-sm leading-relaxed whitespace-pre-line">{hint.body}</p>
	<div class="modal-action">
		<button class="btn btn-primary btn-sm" onclick={() => (hintOpen = false)}>
			{m.CM_CLOSE_BUTTON()}
		</button>
	</div>
</Modal>

<ProxyDialog bind:open={proxyOpen} />
