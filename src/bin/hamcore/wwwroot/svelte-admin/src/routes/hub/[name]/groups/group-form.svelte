<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { number } from '$lib/paraglide/registry';
	import { getLocale } from '$lib/paraglide/runtime';
	import { rpc, VpnRpcSetGroup } from '$lib/rpc';
	import { hubKeys } from '$lib/queryKeys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import { superForm, defaults } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { z } from 'zod';
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import type { Writable } from 'svelte/store';
	import Button from '$lib/components/button.svelte';
	import PageHeader from '$lib/components/page-header.svelte';
	import PolicyEditor from '$lib/components/policy-editor.svelte';
	import {
		POLICIES,
		emptyBoolPolicies,
		emptyNumPolicies,
		emptyNumEnabled,
		defaultBoolPolicies,
		defaultNumPolicies,
		defaultNumEnabled,
		clampPolicy,
		type PolicyFormData
	} from '$lib/group-policy';
	import UsersRoundIcon from '@lucide/svelte/icons/users-round';
	import ActivityIcon from '@lucide/svelte/icons/activity';

	interface Props {
		hub: string;
		name?: string;
	}

	let { hub, name }: Props = $props();

	const locale = getLocale();
	const client = useQueryClient();
	const isEdit = $derived(!!name);

	const query = createQuery(() => ({
		queryKey: hubKeys.group(hub, name ?? ''),
		queryFn: () => rpc.GetGroup(new VpnRpcSetGroup({ HubName_str: hub, Name_str: name })),
		enabled: !!name
	}));

	const schema = z.object({
		groupName: z.string().min(1),
		fullName: z.string().default(''),
		note: z.string().default(''),
		usePolicy: z.boolean().default(false),
		boolPolicies: z.record(z.string(), z.boolean()).default(defaultBoolPolicies()),
		numPolicies: z.record(z.string(), z.number()).default(defaultNumPolicies()),
		numEnabled: z.record(z.string(), z.boolean()).default(defaultNumEnabled())
	});
	type FormData = z.infer<typeof schema>;

	const sf = superForm(defaults(zod4(schema)), {
		dataType: 'json',
		SPA: true,
		validators: zod4Client(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) await saveMutation.mutateAsync(form.data);
		}
	});
	const { form, enhance, errors, submitting, reset } = sf;

	// Populate the form from the loaded group when editing. When the group has no
	// active policy, seed the editor with the SoftEther default policy so enabling
	// it shows sensible values (Allow Access, 32 TCP connections, 20s time-out).
	$effect(() => {
		if (!name || !query.isSuccess || !query.data) return;
		const d = query.data as unknown as Record<string, string | number | boolean>;
		const usePolicy = query.data.UsePolicy_bool;
		let boolPolicies = defaultBoolPolicies();
		let numPolicies = defaultNumPolicies();
		let numEnabled = defaultNumEnabled();
		if (usePolicy) {
			boolPolicies = emptyBoolPolicies();
			numPolicies = emptyNumPolicies();
			numEnabled = emptyNumEnabled();
			for (const p of POLICIES) {
				if (p.type === 'bool') {
					boolPolicies[p.key] = Boolean(d[p.key]);
				} else {
					// A stored value of 0 means the numeric policy is not enforced.
					const v = Number(d[p.key] ?? 0);
					numEnabled[p.key] = v > 0;
					numPolicies[p.key] = v > 0 ? v : (p.min ?? 0);
				}
			}
		}
		reset({
			data: {
				groupName: query.data.Name_str,
				fullName: query.data.Realname_utf,
				note: query.data.Note_utf,
				usePolicy,
				boolPolicies,
				numPolicies,
				numEnabled
			}
		});
	});

	const saveMutation = createMutation(() => ({
		mutationFn: (data: FormData) => {
			const payload = new VpnRpcSetGroup({
				HubName_str: hub,
				Name_str: name ?? data.groupName,
				Realname_utf: data.fullName,
				Note_utf: data.note,
				UsePolicy_bool: data.usePolicy
			});
			Object.assign(payload, data.boolPolicies, { ['policy:Ver3_bool']: true });
			// Numeric policies: send the clamped value when enabled, otherwise undefined
			// (the field is omitted so the server treats the limit as not set).
			const p = payload as unknown as Record<string, number | undefined>;
			for (const item of POLICIES) {
				if (item.type !== 'num') continue;
				p[item.key] = data.numEnabled[item.key]
					? clampPolicy(item, data.numPolicies[item.key] ?? item.min ?? 0)
					: undefined;
			}
			return name ? rpc.SetGroup(payload) : rpc.CreateGroup(payload);
		},
		onSuccess: async () => {
			await client.invalidateQueries({ queryKey: hubKeys.groups(hub) });
			await goto(resolve('/hub/[name]/groups', { name: hub }));
		}
	}));

	const groupsHref = $derived(resolve('/hub/[name]/groups', { name: hub }));

	// Traffic counters shown while editing (mirrors the desktop "Statistical Information").
	let stats = $derived.by(() => {
		const d = query.data;
		if (!d) return [];
		return [
			{ label: m.SM_ST_SEND_UCAST_NUM(), value: d['Send.UnicastCount_u64'] },
			{ label: m.SM_ST_SEND_UCAST_SIZE(), value: d['Send.UnicastBytes_u64'] },
			{ label: m.SM_ST_SEND_BCAST_NUM(), value: d['Send.BroadcastCount_u64'] },
			{ label: m.SM_ST_SEND_BCAST_SIZE(), value: d['Send.BroadcastBytes_u64'] },
			{ label: m.SM_ST_RECV_UCAST_NUM(), value: d['Recv.UnicastCount_u64'] },
			{ label: m.SM_ST_RECV_UCAST_SIZE(), value: d['Recv.UnicastBytes_u64'] },
			{ label: m.SM_ST_RECV_BCAST_NUM(), value: d['Recv.BroadcastCount_u64'] },
			{ label: m.SM_ST_RECV_BCAST_SIZE(), value: d['Recv.BroadcastBytes_u64'] }
		];
	});
</script>

<div class="flex flex-col gap-4 p-4">
	<div class="breadcrumbs text-sm">
		<ul>
			<li><a href={groupsHref}>{m.D_SM_GROUP__CAPTION()}</a></li>
			<li>{isEdit ? name : m.SM_EDIT_GROUP_CAPTION_1()}</li>
		</ul>
	</div>

	<PageHeader
		title={isEdit ? m.SM_EDIT_GROUP_CAPTION_2({ input0: name! }) : m.SM_EDIT_GROUP_CAPTION_1()}>
		{#snippet icon()}
			<UsersRoundIcon size={22} />
		{/snippet}
	</PageHeader>

	{#if isEdit && query.isLoading}
		<div class="h-40 w-full skeleton"></div>
		<div class="h-64 w-full skeleton"></div>
	{:else}
		<form use:enhance class="flex flex-col gap-4">
			<!-- Identity -->
			<div class="card bg-base-100 shadow dark:bg-base-300">
				<div class="card-body">
					<fieldset class="fieldset">
						<label class="label" for="group-name">{m.D_SM_EDIT_GROUP__IDC_STATIC1()}</label>
						<input
							id="group-name"
							type="text"
							class="input w-full max-w-sm input-sm"
							bind:value={$form.groupName}
							readonly={isEdit}
							required />
						{#if $errors.groupName}
							<p class="text-xs text-error">{$errors.groupName}</p>
						{/if}

						<label class="label" for="group-fullname">{m.D_SM_EDIT_GROUP__IDC_STATIC3()}</label>
						<input
							id="group-fullname"
							type="text"
							class="input w-full max-w-sm input-sm"
							bind:value={$form.fullName} />

						<label class="label" for="group-note">{m.D_SM_EDIT_GROUP__IDC_STATIC4()}</label>
						<textarea
							id="group-note"
							class="textarea w-full max-w-sm textarea-sm"
							bind:value={$form.note}>
						</textarea>
					</fieldset>
				</div>
			</div>

			<!-- Statistics (edit only) -->
			{#if isEdit}
				<div class="card bg-base-100 shadow dark:bg-base-300">
					<div class="card-body gap-3">
						<h3 class="flex items-center gap-2 text-lg font-semibold">
							<ActivityIcon size={18} class="opacity-70" />
							{m.D_SM_EDIT_GROUP__S_POLICY_2()}
						</h3>
						<div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
							{#each stats as s (s.label)}
								<div class="rounded-box border border-base-300 p-3 dark:border-base-100">
									<p class="text-xs opacity-60">{s.label}</p>
									<p class="text-lg font-semibold tabular-nums">{number(locale, s.value)}</p>
								</div>
							{/each}
						</div>
					</div>
				</div>
			{/if}

			<!-- Security policy (shared editor, also used by the users page) -->
			<PolicyEditor form={form as unknown as Writable<PolicyFormData>} />

			<!-- Actions -->
			<div class="flex justify-end gap-2">
				<a href={groupsHref} class="btn btn-neutral btn-sm not-dark:btn-soft">
					{m.D_SM_EDIT_ACCESS__IDCANCEL()}
				</a>
				<Button
					type="submit"
					class="btn btn-primary btn-sm"
					loading={$submitting || saveMutation.isPending}
					disabled={$submitting || saveMutation.isPending}>
					{m.D_SM_EDIT_GROUP__IDOK()}
				</Button>
			</div>
		</form>
	{/if}
</div>
