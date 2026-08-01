<script lang="ts">
	import { m } from '$lib/paraglide/messages';
	import {
		rpc,
		Util_Base64_Decode,
		VpnRpcEnumLogFile,
		VpnRpcEnumLogFileItem,
		VpnRpcReadLogFile
	} from '$lib/rpc';
	import { createQuery } from '@tanstack/svelte-query';
	import { hubKeys } from '$lib/rpc/query-keys';
	import type { PageProps } from '../$types';
	import { filesize } from 'filesize';
	import DataTable, { type DataTableColumn } from '$lib/components/ui/data-table.svelte';

	let { params }: PageProps = $props();

	const query = createQuery(() => ({
		queryKey: hubKeys.logFiles(params.name),
		queryFn: rpc.EnumLogFile,
		initialData: new VpnRpcEnumLogFile()
	}));

	const columns: DataTableColumn<VpnRpcEnumLogFileItem>[] = $derived([
		{ header: m.SM_LOG_FILE_COLUMN_1(), value: 'FilePath_str', primary: true },
		{
			header: m.SM_LOG_FILE_COLUMN_2(),
			value: (log) => filesize(log.FileSize_u32),
			sortBy: 'FileSize_u32'
		},
		{ header: m.SM_LOG_FILE_COLUMN_3(), value: 'UpdatedTime_dt', cardSpan: 2 },
		{ header: m.SM_LOG_FILE_COLUMN_4(), value: 'ServerName_str' }
	]);

	async function getLogFile(file: VpnRpcEnumLogFileItem) {
		let buffers: Uint8Array<ArrayBuffer>[] = [];
		let offset = 0;
		while (true) {
			const result = await rpc.ReadLogFile({
				ServerName_str: file.ServerName_str,
				FilePath_str: file.FilePath_str,
				Offset_u32: offset
			} as VpnRpcReadLogFile);

			if (result.Buffer_bin == undefined) break;

			let decoded = Util_Base64_Decode(result.Buffer_bin);

			offset += decoded.byteLength;
			buffers.push(decoded);
		}
		const blob = new Blob(buffers, { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = file.FilePath_str || 'file.log';
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<div>
	<h2 class="ms-4 py-4 text-xl font-bold">{m.D_SM_LOG_FILE__CAPTION()}</h2>
	<div class="max-h-[75vh] overflow-y-auto">
		<DataTable
			rows={query.data.LogFiles}
			{columns}
			rowKey={(log) => log.FilePath_str}
			loading={query.isFetching && query.data.LogFiles.length === 0}
			rowsPerPage={20}
			searchable
			tableClass="table-pin-rows table-xs"
			onrowdblclick={getLogFile} />
	</div>
</div>
