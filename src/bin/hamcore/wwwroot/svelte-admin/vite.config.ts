import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';

export default defineConfig(async ({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '');

	return {
		plugins: [
			paraglideVitePlugin({
				project: './project.inlang',
				outdir: './src/lib/paraglide',
				strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
				emitTsDeclarations: true
			}),
			tailwindcss(),
			sveltekit()
		],
		server: {
			proxy: {
				'/api': {
					target: env['RPC_SERVER_URL'],
					changeOrigin: true,
					secure: false,
					preserveHeaderKeyCase: true
				}
			}
		}
	};
});
