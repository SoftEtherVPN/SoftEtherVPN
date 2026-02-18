<script lang="ts" module>
	import { z } from 'zod';

	const schema = z.object({
		name: z.string(),
		password: z.string(),
		confirmPassword: z.string(),
		noEnum: z.boolean(),
		status: z.enum(['online', 'offline']),
		hubType: z.enum(['static', 'dynamic']),
		limitMaxSession: z.boolean(),
		maxSession: z.int()
	});
</script>

<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Card, CardFooter, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { m } from '$lib/paraglide/messages';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4, zod4Client } from 'sveltekit-superforms/adapters';
	import { Input } from '$lib/components/ui/input';
	import {
		Field,
		FieldContent,
		FieldDescription,
		FieldGroup,
		FieldLabel,
		FieldLegend,
		FieldSeparator,
		FieldSet
	} from '$lib/components/ui/field';
	import CardContent from '$lib/components/ui/card/card-content.svelte';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { RadioGroup, RadioGroupItem } from '$lib/components/ui/radio-group';

	const form = superForm(defaults(zod4(schema)), {
		SPA: true,
		validators: zod4Client(schema)
	});

	const { form: formData, enhance } = form;
</script>

<Card class="mx-auto w-full max-w-3xl rounded-none sm:rounded-xl">
	<CardHeader class="pb-4">
		<CardTitle>{m.CM_EDIT_HUB_1()}</CardTitle>
	</CardHeader>
	<CardContent class="pb-4">
		<form use:enhance>
			<FieldGroup class="gap-4">
				<!-- Hub Name -->
				<FieldSet class="gap-3">
					<FieldLabel class="text-sm font-semibold">
						{m.D_SM_EDIT_HUB__STATIC1()}
					</FieldLabel>
					<Input class="w-full" />
				</FieldSet>

				<FieldSeparator />

				<!-- Security Settings (left) + Set Clustering & Virtual Hub Status (right) -->
				<div class="grid grid-cols-1 gap-x-12 gap-y-4 md:grid-cols-2">
					<!-- Left: Security Settings -->
					<FieldSet class="gap-4">
						<FieldLegend class="text-sm font-semibold">
							{m.D_SM_EDIT_HUB__STATIC2()}
						</FieldLegend>

						<FieldDescription class="text-xs">{m.D_SM_EDIT_HUB__S_BOLD()}</FieldDescription>

						<Field orientation="vertical" class="gap-2">
							<FieldContent>
								<FieldLabel>{m.D_SM_EDIT_HUB__STATIC3()}</FieldLabel>
							</FieldContent>
							<Input type="password" class="w-full" />
						</Field>

						<Field orientation="vertical" class="gap-2">
							<FieldContent>
								<FieldLabel>{m.D_SM_EDIT_HUB__STATIC4()}</FieldLabel>
							</FieldContent>
							<Input type="password" class="w-full" />
						</Field>

						<Field orientation="horizontal" class="items-center gap-2">
							<Checkbox name="noEnum" />
							<FieldContent>
								<FieldLabel class="font-normal">{m.D_SM_EDIT_HUB__R_NO_ENUM()}</FieldLabel>
							</FieldContent>
						</Field>
					</FieldSet>

					<!-- Mobile separator -->
					<FieldSeparator class="md:hidden" />

					<!-- Right: Set Clustering + Virtual Hub Status -->
					<div class="flex flex-col gap-4">
						<FieldSet class="gap-3">
							<FieldLegend class="text-sm font-semibold">
								{m.D_SM_EDIT_HUB__STATIC7()}
							</FieldLegend>

							<FieldDescription class="text-xs">{m.D_SM_EDIT_HUB__STATIC8()}</FieldDescription>

							<RadioGroup value="online" class="flex flex-row gap-6">
								<Field orientation="horizontal" class="items-center gap-2">
									<RadioGroupItem value="online" id="status-online" />
									<FieldContent>
										<FieldLabel for="status-online" class="font-normal">
											{m.D_SM_EDIT_HUB__R_ONLINE()}
										</FieldLabel>
									</FieldContent>
								</Field>
								<Field orientation="horizontal" class="items-center gap-2">
									<RadioGroupItem value="offline" id="status-offline" />
									<FieldContent>
										<FieldLabel for="status-offline" class="font-normal">
											{m.D_SM_EDIT_HUB__R_OFFLINE()}
										</FieldLabel>
									</FieldContent>
								</Field>
							</RadioGroup>
						</FieldSet>

						<FieldSeparator />

						<FieldSet class="gap-3">
							<FieldLegend class="text-sm font-semibold">
								{m.D_SM_EDIT_HUB__STATIC9()}
							</FieldLegend>

							<FieldDescription class="text-xs text-muted-foreground">
								{m.CM_EDIT_HUB_STANDALONE()}
							</FieldDescription>

							<RadioGroup value="static" class="gap-2">
								<Field orientation="horizontal" class="items-center gap-2">
									<RadioGroupItem value="static" id="hub-static" />
									<FieldContent>
										<FieldLabel for="hub-static" class="font-normal">
											{m.D_SM_EDIT_HUB__R_STATIC()}
										</FieldLabel>
									</FieldContent>
								</Field>
								<Field orientation="horizontal" class="items-center gap-2">
									<RadioGroupItem value="dynamic" id="hub-dynamic" />
									<FieldContent>
										<FieldLabel for="hub-dynamic" class="font-normal">
											{m.D_SM_EDIT_HUB__R_DYNAMIC()}
										</FieldLabel>
									</FieldContent>
								</Field>
							</RadioGroup>
						</FieldSet>
					</div>
				</div>

				<FieldSeparator />

				<!-- Virtual Hub Options -->
				<FieldSet class="gap-3">
					<FieldLegend class="text-sm font-semibold">
						{m.D_SM_EDIT_HUB__STATIC5()}
					</FieldLegend>

					<div class="flex flex-wrap items-center gap-x-6 gap-y-3">
						<Field orientation="horizontal" class="items-center gap-2">
							<Checkbox name="limitMaxSession" />
							<FieldContent>
								<FieldLabel class="font-normal">
									{m.D_SM_EDIT_HUB__R_LIMIT_MAX_SESSION()}
								</FieldLabel>
							</FieldContent>
						</Field>

						<div class="flex items-center gap-2">
							<FieldLabel class="shrink-0 text-sm">{m.D_SM_EDIT_HUB__S_MAX_SESSION_1()}</FieldLabel>
							<Input type="number" min="1" class="w-24" />
							<span class="text-sm text-muted-foreground">
								{m.D_SM_EDIT_HUB__S_MAX_SESSION_2()}
							</span>
						</div>
					</div>

					<FieldDescription class="text-xs text-muted-foreground">
						{m.D_SM_EDIT_HUB__STATIC6()}
					</FieldDescription>
				</FieldSet>
			</FieldGroup>
		</form>
	</CardContent>
	<CardFooter class="flex justify-end gap-2 border-t pt-4">
		<Button variant="outline">{m.D_SM_EDIT_HUB__IDCANCEL()}</Button>
		<Button>{m.D_SM_EDIT_HUB__IDOK()}</Button>
	</CardFooter>
</Card>
