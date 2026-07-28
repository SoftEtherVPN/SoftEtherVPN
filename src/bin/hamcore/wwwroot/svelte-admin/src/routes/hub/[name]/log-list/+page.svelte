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
	import type { PageProps } from '../$types';
	import { filesize } from 'filesize';

	let { params }: PageProps = $props();

	const query = createQuery(() => ({
		queryKey: ['hub', params.name, 'log-list'],
		queryFn: rpc.EnumLogFile,
		initialData: new VpnRpcEnumLogFile()
	}));

	async function getLogFile(file: VpnRpcEnumLogFileItem) {
		let buffers: Uint8Array<ArrayBuffer>[] = [];
		let offset = 0;
		while (true) {
			const result = await rpc.ReadLogFile({
				ServerName_str: file.ServerName_str,
				FilePath_str: file.FilePath_str,
				Offset_u32: offset
			} as VpnRpcReadLogFile);
			debugger;

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
		<table class="table-pin-rows table table-xs">
			<thead>
				<tr>
					<th>{m.SM_LOG_FILE_COLUMN_1()}</th>
					<th>{m.SM_LOG_FILE_COLUMN_2()}</th>
					<th>{m.SM_LOG_FILE_COLUMN_3()}</th>
					<th>{m.SM_LOG_FILE_COLUMN_4()}</th>
				</tr>
			</thead>
			<tbody>
				{#each query.data.LogFiles as log (log.FilePath_str)}
					<tr ondblclick={() => getLogFile(log)}>
						<td>{log.FilePath_str}</td>
						<td>{filesize(log.FileSize_u32)}</td>
						<td>{log.UpdatedTime_dt}</td>
						<td>{log.ServerName_str}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
</div>
