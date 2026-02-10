<script lang="ts">
	import { isNumber } from '$lib/utils/is-number';
	import { cn } from '$lib/utils.js';
	import type { HTMLAttributes } from 'svelte/elements';

	type Props = {
		value?: number | string | null;
		goNext?: () => void;
		goPrevious?: () => void;
		ref?: HTMLInputElement;
	};

	let {
		value = $bindable(null),
		goPrevious,
		goNext,
		ref = $bindable(),
		class: className,
		...rest
	}: Props & HTMLAttributes<HTMLInputElement> = $props();

	/** Runs after input (this is here because safari/firefox treat the `setTimeout` function differently than chrome) */
	let after: (() => void) | undefined = undefined;

	const onKeydown = (e: KeyboardEvent) => {
		if (e.ctrlKey || e.metaKey) return;

		// just continue as normal
		if (e.key == 'Tab' || e.key == 'Delete') return;

		// for backspace we goPrevious if the value is empty
		if (e.key == 'Backspace') {
			if (value == null || value.toString().length == 0) {
				// the 2 ensures consistent behavior in all browsers
				setTimeout(() => goPrevious?.(), 2);
			}
			return;
		}

		// we want to go forward for `.` or ` `
		if (['.', ' '].includes(e.key) && !e.ctrlKey && !e.metaKey) {
			e.preventDefault();
			goNext?.();
			return;
		}

		const target = e.target as HTMLInputElement;

		if (e.key == 'ArrowRight') {
			// only go to next box if at end
			if (target.selectionStart == target.value.length) {
				e.preventDefault();
				goNext?.();
			}
			return;
		}

		if (e.key == 'ArrowLeft') {
			// only go to previous box if at start
			if (target.selectionStart == 0) {
				e.preventDefault();
				goPrevious?.();
			}
			return;
		}

		// disallow any non numbers
		// By default this prevents any undefined behavior
		// so make sure anything that can happen is defined.
		if (!isNumber(e.key)) {
			e.preventDefault();
			return;
		}

		const newValue = (e.target as HTMLInputElement).value + e.key;

		if (newValue.length > 3) {
			e.preventDefault();
			goNext?.();
			return;
		}

		const integerValue = parseInt(newValue);

		// we will try to advance if its greater
		if (integerValue > 255) {
			e.preventDefault();
			goNext?.();
			return;
		}

		// this should be impossible but in any case
		if (integerValue < 0) {
			e.preventDefault();
			return;
		}

		if (newValue.length == 3) {
			// go next after input
			after = () => goNext?.();
			return;
		}
	};

	const onInput = () => {
		after?.();
		after = undefined;
	};
</script>

<input
	bind:this={ref}
	min={0}
	max={255}
	maxlength={3}
	bind:value
	oninput={onInput}
	onkeydown={onKeydown}
	type="text"
	class={cn(
		'hide-ramp placeholder:text-muted-foreground h-full w-9 border-0 bg-transparent text-center outline-hidden focus:outline-hidden',
		className
	)}
	{...rest}
/>

<style lang="postcss">
	.hide-ramp::-webkit-inner-spin-button,
	.hide-ramp::-webkit-outer-spin-button {
		-webkit-appearance: none;
		margin: 0;
	}
</style>
