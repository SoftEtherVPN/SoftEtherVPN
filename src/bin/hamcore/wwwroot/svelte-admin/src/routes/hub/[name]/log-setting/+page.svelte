<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import { hubKeys } from '$lib/rpc/query-keys';
	import { createMutation, createQuery, useQueryClient } from '@tanstack/svelte-query';
	import type { PageProps } from './$types';
	import { rpc, VpnRpcHubLog, VpnRpcLogSwitchType, VpnRpcPacketLogSetting } from '$lib/rpc';
	import z from 'zod';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { Control, ElementField, Field, Fieldset, Label } from 'formsnap';
	import { translatePacketLog } from '$lib/rpc/labels';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import Button from '$lib/components/ui/button.svelte';

	let { params }: PageProps = $props();

	const client = useQueryClient();
	const query = createQuery(() => ({
		queryKey: hubKeys.logSetting(params.name),
		queryFn: () => rpc.GetHubLog(new VpnRpcHubLog({ HubName_str: params.name }))
	}));

	const mutation = createMutation(() => ({
		mutationFn: rpc.SetHubLog,
		onSuccess: () => {
			client.invalidateQueries({ queryKey: hubKeys.logSetting(params.name) });
		}
	}));

	const schema = z.object({
		saveSecurityLog: z.boolean(),
		securityLogCycle: z.enum(VpnRpcLogSwitchType),
		savePacketLog: z.boolean(),
		packetLogCycle: z.enum(VpnRpcLogSwitchType),
		packetLogs: z.array(z.enum(VpnRpcPacketLogSetting)).length(8)
	});

	const sf = superForm(defaults(zod4(schema)), {
		SPA: true,
		validators: zod4Client(schema),
		resetForm: false,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				await mutation.mutateAsync({
					HubName_str: params.name,
					SaveSecurityLog_bool: form.data.saveSecurityLog,
					SecurityLogSwitchType_u32: form.data.securityLogCycle,
					SavePacketLog_bool: form.data.savePacketLog,
					PacketLogSwitchType_u32: form.data.packetLogCycle,
					PacketLogConfig_u32: [...form.data.packetLogs, 0, 0, 0, 0, 0, 0, 0, 0]
				});
			}
		}
	});
	const { form, enhance, submitting, reset } = sf;

	$effect(() => {
		if (!query.isSuccess || !query.data) return;
		reset({
			data: {
				saveSecurityLog: query.data.SaveSecurityLog_bool,
				securityLogCycle: query.data.SecurityLogSwitchType_u32,
				savePacketLog: query.data.SavePacketLog_bool,
				packetLogCycle: query.data.PacketLogSwitchType_u32,
				packetLogs: query.data.PacketLogConfig_u32.slice(0, 8)
			}
		});
	});
</script>

{#snippet cycleOption()}
	<option value={VpnRpcLogSwitchType.No}>{m.SM_LOG_SWITCH_0()}</option>
	<option value={VpnRpcLogSwitchType.Second}>{m.SM_LOG_SWITCH_1()}</option>
	<option value={VpnRpcLogSwitchType.Minute}>{m.SM_LOG_SWITCH_2()}</option>
	<option value={VpnRpcLogSwitchType.Hour}>{m.SM_LOG_SWITCH_3()}</option>
	<option value={VpnRpcLogSwitchType.Day}>{m.SM_LOG_SWITCH_4()}</option>
	<option value={VpnRpcLogSwitchType.Month}>{m.SM_LOG_SWITCH_5()}</option>
{/snippet}

<div class="p-4">
	<h2 class="text-xl font-bold">{m.D_SM_LOG__CAPTION()}</h2>
	<span class="text-sm font-light">{m.D_SM_LOG__S_TITLE({ input0: params.name })}</span>

	{#if query.isLoading}
		<div class="mt-4 h-60 w-full skeleton"></div>
	{:else}
		<form use:enhance>
			<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
				<legend class="fieldset-legend">{m.D_SM_LOG__STATIC1()}</legend>
				<Field form={sf} name="saveSecurityLog">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="toggle toggle-primary toggle-sm"
									bind:checked={$form.saveSecurityLog} />
								{m.D_SM_LOG__B_SEC()}
							</Label>
						{/snippet}
					</Control>
				</Field>
				<div class="flex justify-end">
					<Field form={sf} name="securityLogCycle">
						<Control>
							{#snippet children({ props })}
								<Label class="label">
									{m.D_SM_LOG__S_PACKET()}
									<select
										{...props}
										class="select min-w-3xs select-sm"
										bind:value={$form.securityLogCycle}>
										{@render cycleOption()}
									</select>
								</Label>
							{/snippet}
						</Control>
					</Field>
				</div>
			</fieldset>

			<fieldset class="fieldset rounded-box border border-base-300 bg-base-200 p-4">
				<legend class="fieldset-legend">{m.D_SM_LOG__STATIC2()}</legend>
				<Field form={sf} name="savePacketLog">
					<Control>
						{#snippet children({ props })}
							<Label class="label">
								<input
									{...props}
									type="checkbox"
									class="toggle toggle-primary toggle-sm"
									bind:checked={$form.savePacketLog} />
								{m.D_SM_LOG__B_PACKET()}
							</Label>
						{/snippet}
					</Control>
				</Field>
				<div class="flex justify-end">
					<Field form={sf} name="packetLogCycle">
						<Control>
							{#snippet children({ props })}
								<Label class="label">
									{m.D_SM_LOG__S_PACKET()}
									<select
										{...props}
										class="select min-w-3xs select-sm"
										bind:value={$form.packetLogCycle}>
										{@render cycleOption()}
									</select>
								</Label>
							{/snippet}
						</Control>
					</Field>
				</div>

				<div>
					<Fieldset form={sf} name="packetLogs">
						<!---->
						{#each { length: 8 }, i}
							<div class="mt-4 grid grid-cols-4">
								<span>{translatePacketLog(i)}</span>
								<ElementField form={sf} name="packetLogs[{i}]">
									<Control>
										{#snippet children({ props })}
											<Label class="label">
												<input
													{...props}
													type="radio"
													class="radio radio-sm"
													name="packetLogs[{i}]"
													bind:group={$form.packetLogs[i]}
													value={VpnRpcPacketLogSetting.None} />
												{m.D_SM_LOG__B_PACKET_0_0()}
											</Label>
										{/snippet}
									</Control>
									<Control>
										{#snippet children({ props })}
											<Label class="label">
												<input
													{...props}
													type="radio"
													class="radio radio-sm"
													name="packetLogs[{i}]"
													bind:group={$form.packetLogs[i]}
													value={VpnRpcPacketLogSetting.Header} />
												{m.D_SM_LOG__B_PACKET_0_1()}
											</Label>
										{/snippet}
									</Control>
									<Control>
										{#snippet children({ props })}
											<Label class="label">
												<input
													{...props}
													type="radio"
													class="radio radio-sm"
													name="packetLogs[{i}]"
													bind:group={$form.packetLogs[i]}
													value={VpnRpcPacketLogSetting.All} />
												{m.D_SM_LOG__B_PACKET_0_2()}
											</Label>
										{/snippet}
									</Control>
								</ElementField>
							</div>
						{/each}
					</Fieldset>
				</div>
			</fieldset>
			<div class="mt-4 alert alert-soft alert-warning">
				<TriangleAlertIcon size={18} />
				<p>{m.D_SM_LOG__STATIC3()}</p>
			</div>
			<div class="flex justify-end gap-2">
				<Button
					type="submit"
					class="btn btn-primary btn-sm"
					disabled={$submitting}
					loading={$submitting}>
					{m.D_SM_LOG__IDOK()}
				</Button>
				<button type="reset" class="btn btn-secondary btn-sm">{m.D_SM_LOG__IDCANCEL()}</button>
			</div>
		</form>
	{/if}
</div>
