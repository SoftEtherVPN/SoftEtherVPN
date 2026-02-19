import { compile } from '@inlang/paraglide-js';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(async ({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '');
	const isPROD = mode == 'production';
	await compile({
		project: './project.inlang',
		outdir: './src/lib/paraglide',
		strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
		emitTsDeclarations: true,
		outputStructure: isPROD ? 'message-modules' : 'locale-modules',
		isServer: "import.meta.env?.SSR ?? typeof window === 'undefined'"
	});

	return {
		plugins: [tailwindcss(), sveltekit()],
		server: {
			proxy: {
				'/api': {
					target: env['RPC_SERVER_URL'],
					changeOrigin: true,
					secure: false
				}
			}
		}
	};
});
