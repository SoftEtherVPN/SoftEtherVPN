<script lang="ts">
	import { FieldErrors, type FieldErrorsProps } from 'formsnap';
	import { FieldError } from '../ui/field';

	let props: FieldErrorsProps = $props();
</script>

<FieldErrors {...props}>
	{#snippet children({ errors, errorProps })}
		<FieldError {...errorProps} errors={errors.map((e) => ({ message: e }))} />
	{/snippet}
</FieldErrors>
