import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		// adapter-auto only supports some environments, see https://svelte.dev/docs/kit/adapter-auto for a list.
		// If your environment is not supported, or you settled on a specific environment, switch out the adapter.
		// See https://svelte.dev/docs/kit/adapters for more information about adapters.
		adapter: adapter({
			fallback: '200.html'
		}),
		paths: {
			relative: false
		},
		router: { type: 'hash' },
		// The two hard dependencies on the rest of the SoftEther tree. Keeping them
		// behind aliases means relocating this project is a change to these two
		// lines instead of a rewrite of every `../../../..` in the source.
		alias: {
			$vpnrpc:
				'../../../../../developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-typescript/vpnrpc',
			$pencore: '../../../../PenCore'
		}
	},
	compilerOptions: {
		runes: true
	}
};

export default config;
