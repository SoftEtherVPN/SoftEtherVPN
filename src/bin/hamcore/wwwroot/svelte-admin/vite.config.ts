import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { convertStb } from './convert-stb';

export default defineConfig(async ({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '');

	await convertStb();

	return {
		plugins: [
			tailwindcss(),
			sveltekit(),
			paraglideVitePlugin({
				project: './project.inlang',
				outdir: './src/lib/paraglide',
				strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
				emitTsDeclarations: true
			})
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
