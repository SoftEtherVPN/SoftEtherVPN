<script lang="ts" module>
	import type { Snippet } from 'svelte';

	/** Property name, or a function deriving a value from a row. */
	export type DataTableField<T> = keyof T | ((row: T) => unknown);

	type DataTableColumnBase<T> = {
		/** Header text, already localized by the caller. */
		header: string;
		/**
		 * Makes the column sortable. Defaults to `value` when the column has one,
		 * so most columns never need it. Pass `false` to opt out.
		 */
		sortBy?: DataTableField<T> | false;
		/** Used as the card title on narrow screens. Defaults to the first column. */
		primary?: boolean;
		/** Keep this column out of the card layout. */
		cardHidden?: boolean;
		/** How many of the two card grid columns this value spans. */
		cardSpan?: 1 | 2;
		/** Extra classes for the `<td>`. */
		class?: string;
		/** Extra classes for the `<th>`. */
		headerClass?: string;
	};

	/**
	 * One column of a {@link DataTable}. The same declaration drives both the
	 * table rendered on wide screens and the card list rendered on narrow ones.
	 *
	 * A column renders either a plain `value` — the common case, no snippet
	 * needed — or a `cell` snippet when it needs markup. Never both.
	 */
	export type DataTableColumn<T> =
		| (DataTableColumnBase<T> & { value: DataTableField<T>; cell?: never })
		| (DataTableColumnBase<T> & { cell: Snippet<[T]>; value?: never });
</script>

<script lang="ts" generics="T extends Record<string, any>">
	import { untrack } from 'svelte';
	import { TableHandler } from '@vincjo/datatables';
	import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import ChevronUpIcon from '@lucide/svelte/icons/chevron-up';
	import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import SearchIcon from '@lucide/svelte/icons/search';

	interface Props {
		/** Rows to display. Usually a TanStack Query result. */
		rows: T[];
		/**
		 * Column set. May be `$derived` so headers follow the locale, but the
		 * number and order of columns must stay stable: sorting is bound to the
		 * initial column positions.
		 */
		columns: DataTableColumn<T>[];
		/** Stable identity of a row, used for selection and for `{#each}` keys. */
		rowKey: (row: T) => string | number;
		/**
		 * Key of the selected row, or `undefined`. Bindable. The key is exposed
		 * rather than the row itself so that it survives a refetch; derive the
		 * row from your own data with `.find()`.
		 */
		selectedKey?: string | number;
		/** Shows a skeleton instead of the rows. */
		loading?: boolean;
		/** Enables client-side pagination. Omit to show every row. */
		rowsPerPage?: number;
		/** Enables the client-side search box. */
		searchable?: boolean;
		searchPlaceholder?: string;
		previousLabel?: string;
		nextLabel?: string;
		/** Called on double click, typically to open the row. */
		onrowdblclick?: (row: T) => void;
		/**
		 * Trailing per-row cell, for a row menu. Rendered once per layout, so the
		 * second argument is a DOM-safe id unique to this row *and* this layout —
		 * use it for `popovertarget` and anchor names.
		 */
		rowActions?: Snippet<[T, string]>;
		/** Shown instead of the table when there is no row at all. */
		empty?: Snippet;
		/** Toolbar rendered below the table. */
		actions?: Snippet;
		class?: string;
		tableClass?: string;
		skeletonRows?: number;
	}

	let {
		rows,
		columns,
		rowKey,
		selectedKey = $bindable(),
		loading = false,
		rowsPerPage,
		searchable = false,
		searchPlaceholder,
		previousLabel = 'Previous',
		nextLabel = 'Next',
		onrowdblclick,
		rowActions,
		empty,
		actions,
		class: className,
		tableClass,
		skeletonRows = 4
	}: Props = $props();

	const uid = $props.id();

	// `@vincjo/datatables` is used purely as the data layer — sorting, searching
	// and paging. All the markup below is ours, so it follows the DaisyUI theme.
	// These three are read once on purpose: the handler and its sort builders are
	// created a single time and then kept in sync through `setRows` below.
	const table = new TableHandler<T>([], { rowsPerPage: untrack(() => rowsPerPage) });
	const search = untrack(() => searchable) ? table.createSearch() : undefined;
	// A sort builder carries its own identity, so recreating them on every render
	// would drop the active sort. Indexes match `columns`.
	const sorts = untrack(() =>
		columns.map((column) => {
			// A column sorts on its own value unless it says otherwise, so a plain
			// `{ header, value }` column is sortable without extra declaration.
			const field = column.sortBy === undefined ? column.value : column.sortBy;
			return field === undefined || field === false ? undefined : table.createSort(field);
		})
	);

	$effect(() => {
		table.setRows(rows);
	});

	function cellValue(column: DataTableColumn<T>, row: T) {
		if (column.value === undefined) return '';
		return typeof column.value === 'function' ? column.value(row) : row[column.value];
	}

	function isSelected(row: T) {
		return selectedKey !== undefined && selectedKey === rowKey(row);
	}

	function toggle(row: T) {
		selectedKey = isSelected(row) ? undefined : rowKey(row);
	}

	const columnCount = $derived(columns.length + (rowActions ? 1 : 0));
	const showEmpty = $derived(!loading && rows.length === 0);
	const primaryColumn = $derived(columns.find((column) => column.primary) ?? columns[0]);
	const cardColumns = $derived(
		columns.filter((column) => column !== primaryColumn && !column.cardHidden)
	);
</script>

<!-- A column renders either its `cell` snippet or its plain `value`. -->
{#snippet renderCell(column: DataTableColumn<T>, row: T)}
	{#if column.cell}
		{@render column.cell(row)}
	{:else}
		{cellValue(column, row)}
	{/if}
{/snippet}

<div class={['flex flex-col gap-3', className]}>
	{#if searchable && search}
		<label class="input w-full max-w-xs input-sm">
			<SearchIcon size={16} class="opacity-60" />
			<input
				type="search"
				placeholder={searchPlaceholder}
				bind:value={search.value}
				oninput={() => search.set()} />
		</label>
	{/if}

	{#if showEmpty && empty}
		{@render empty()}
	{:else}
		<!-- Wide screens: a real table. -->
		<div class="hidden overflow-x-auto sm:block">
			<table class={['table', tableClass]}>
				<thead>
					<tr>
						{#each columns as column, i (i)}
							{@const sort = sorts[i]}
							<th class={column.headerClass}>
								{#if sort}
									<button
										type="button"
										class="inline-flex cursor-pointer items-center gap-1"
										onclick={() => sort.set()}>
										{column.header}
										{#if !sort.isActive}
											<ChevronsUpDownIcon size={12} class="opacity-40" />
										{:else if sort.direction === 'asc'}
											<ChevronUpIcon size={12} />
										{:else}
											<ChevronDownIcon size={12} />
										{/if}
									</button>
								{:else}
									{column.header}
								{/if}
							</th>
						{/each}
						{#if rowActions}
							<th class="w-10"></th>
						{/if}
					</tr>
				</thead>
				<tbody>
					{#if loading}
						{#each Array.from({ length: skeletonRows }) as _, i (i)}
							<tr>
								<td colspan={columnCount}>
									<div class="h-5 w-full skeleton"></div>
								</td>
							</tr>
						{/each}
					{:else}
						{#each table.rows as row, rowIndex (rowKey(row))}
							<tr
								class="cursor-pointer hover:bg-base-300"
								class:bg-base-200={isSelected(row)}
								onclick={() => toggle(row)}
								ondblclick={() => onrowdblclick?.(row)}>
								{#each columns as column, i (i)}
									<td class={column.class}>{@render renderCell(column, row)}</td>
								{/each}
								{#if rowActions}
									<td class="text-end">{@render rowActions(row, `${uid}-t${rowIndex}`)}</td>
								{/if}
							</tr>
						{/each}
					{/if}
				</tbody>
			</table>
		</div>

		<!-- Narrow screens: the same columns, stacked as cards. -->
		<div class="flex flex-col gap-2 sm:hidden">
			{#if loading}
				{#each Array.from({ length: skeletonRows }) as _, i (i)}
					<div class="h-28 w-full skeleton"></div>
				{/each}
			{:else}
				{#each table.rows as row, rowIndex (rowKey(row))}
					<div
						role="button"
						tabindex="0"
						class={[
							'rounded-box border p-3',
							isSelected(row) ? 'border-primary bg-base-200' : 'border-base-300'
						]}
						onclick={() => toggle(row)}
						ondblclick={() => onrowdblclick?.(row)}
						onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && toggle(row)}>
						<div class="flex items-center justify-between gap-2">
							{#if primaryColumn}
								<span class="min-w-0 truncate font-medium">
									{@render renderCell(primaryColumn, row)}
								</span>
							{/if}
							{#if rowActions}
								{@render rowActions(row, `${uid}-c${rowIndex}`)}
							{/if}
						</div>
						{#if cardColumns.length > 0}
							<div class="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
								{#each cardColumns as column, i (i)}
									<div class={column.cardSpan === 2 ? 'col-span-2' : undefined}>
										<span class="opacity-60">{column.header}</span>
										<br />
										{@render renderCell(column, row)}
									</div>
								{/each}
							</div>
						{/if}
					</div>
				{/each}
			{/if}
		</div>

		{#if rowsPerPage && table.pageCount > 1}
			<div class="flex flex-wrap items-center justify-between gap-2">
				<span class="text-xs tabular-nums opacity-60">
					{table.rowCount.start}–{table.rowCount.end} / {table.rowCount.total}
				</span>
				<div class="join">
					<button
						type="button"
						class="btn join-item btn-sm"
						aria-label={previousLabel}
						disabled={table.currentPage === 1}
						onclick={() => table.setPage('previous')}>
						<ChevronLeftIcon size={14} />
					</button>
					{#each table.pagesWithEllipsis as page, i (i)}
						{#if page === undefined}
							<button type="button" class="btn btn-disabled join-item btn-sm">…</button>
						{:else}
							<button
								type="button"
								class="btn join-item btn-sm"
								class:btn-active={page === table.currentPage}
								onclick={() => table.setPage(page)}>
								{page}
							</button>
						{/if}
					{/each}
					<button
						type="button"
						class="btn join-item btn-sm"
						aria-label={nextLabel}
						disabled={table.currentPage === table.pageCount}
						onclick={() => table.setPage('next')}>
						<ChevronRightIcon size={14} />
					</button>
				</div>
			</div>
		{/if}
	{/if}

	{#if actions}
		{@render actions()}
	{/if}
</div>
