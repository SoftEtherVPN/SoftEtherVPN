<script lang="ts">
	import { cn } from '$lib/utils.js';
	import Input from '$lib/components/ui/ipv4address-input/ipv4address-input-input.svelte';
	import { safeParseIPv4Address } from '$lib/components/ui/ipv4address-input';
	import { isNumber } from '$lib/utils/is-number';
	import * as ipv4address from '$lib/utils/ipv4-address';
	import type { IPv4AddressInputProps } from '$lib/components/ui/ipv4address-input/types';

	let {
		separator = '$lib/components/ui/ipv4address-input',
		value = $bindable(null),
		placeholder,
		class: className,
		name,
		valid = $bindable(false)
	}: IPv4AddressInputProps = $props();

	const parsedPlaceholder = $derived(safeParseIPv4Address(placeholder));

	let firstInput = $state<HTMLInputElement>();
	let secondInput = $state<HTMLInputElement>();
	let thirdInput = $state<HTMLInputElement>();
	let fourthInput = $state<HTMLInputElement>();

	type PartialOctet = number | string | null;

	type PartialOctets = [PartialOctet, PartialOctet, PartialOctet, PartialOctet];

	const octets: PartialOctets = $derived(safeParseIPv4Address(value ?? '') ?? [0, 0, 0, 0]);

	const paste = (e: ClipboardEvent) => {
		const data = e.clipboardData?.getData('text');

		if (!data) return;

		const parsed = safeParseIPv4Address(data);

		if (!parsed) return;

		// validates each octet if invalid then sets to null
		octets[0] = validate(parsed[0]);
		octets[1] = validate(parsed[1]);
		octets[2] = validate(parsed[2]);
		octets[3] = validate(parsed[3]);
	};

	const validate = (octet: string | null): number | null => {
		if (octet == null) return null;

		if (!isNumber(octet)) return null;

		const val = parseInt(octet);

		if (val < 0 || val > 255) return null;

		return val;
	};

	const format = (octets: PartialOctets): string => octets.join(separator);

	$effect(() => {
		valid = ipv4address.parse(value ?? '').isOk();
	});
</script>

<div
	aria-invalid={!valid}
	class={cn(
		'ring-offset-background border-input bg-background selection:bg-primary dark:bg-input/30 focus-within:ring-ring flex h-9 w-fit place-items-center rounded-md border px-3 font-mono font-light ring-2 ring-transparent focus-within:ring-offset-2',
		className
	)}
>
	<Input
		bind:ref={firstInput}
		goNext={() => secondInput?.focus()}
		bind:value={
			() => octets[0],
			(v) => {
				const tempOctets = octets;

				if (v == null || v === '') {
					tempOctets[0] = null;
				} else {
					tempOctets[0] = v;
				}

				value = format(tempOctets);
			}
		}
		placeholder={parsedPlaceholder ? parsedPlaceholder[0] : undefined}
		onpaste={paste}
	/>
	<span class="font-mono">{separator}</span>
	<Input
		bind:ref={secondInput}
		goNext={() => thirdInput?.focus()}
		goPrevious={() => firstInput?.focus()}
		bind:value={
			() => octets[1],
			(v) => {
				const tempOctets = octets;

				if (v == null || v === '') {
					tempOctets[1] = null;
				} else {
					tempOctets[1] = v;
				}

				value = format(tempOctets);
			}
		}
		placeholder={parsedPlaceholder ? parsedPlaceholder[1] : undefined}
		onpaste={paste}
	/>
	<span class="font-mono">{separator}</span>
	<Input
		bind:ref={thirdInput}
		goNext={() => fourthInput?.focus()}
		goPrevious={() => secondInput?.focus()}
		bind:value={
			() => octets[2],
			(v) => {
				const tempOctets = octets;

				if (v == null || v === '') {
					tempOctets[2] = null;
				} else {
					tempOctets[2] = v;
				}

				value = format(tempOctets);
			}
		}
		placeholder={parsedPlaceholder ? parsedPlaceholder[2] : undefined}
		onpaste={paste}
	/>
	<span class="font-mono">{separator}</span>
	<Input
		bind:ref={fourthInput}
		goPrevious={() => thirdInput?.focus()}
		bind:value={
			() => octets[3],
			(v) => {
				const tempOctets = octets;

				if (v == null || v === '') {
					tempOctets[3] = null;
				} else {
					tempOctets[3] = v;
				}

				value = format(tempOctets);
			}
		}
		placeholder={parsedPlaceholder ? parsedPlaceholder[3] : undefined}
		onpaste={paste}
	/>
</div>
<input class="hidden" {name} {value} />
