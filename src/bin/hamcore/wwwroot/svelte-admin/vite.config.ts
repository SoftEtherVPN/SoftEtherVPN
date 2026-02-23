import { compile } from '@inlang/paraglide-js';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import fs from 'node:fs';
import path from 'node:path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(async ({ mode }) => {
	const env = loadEnv(mode, process.cwd(), '');
	const isPROD = mode == 'production';

	const messageDir = path.join(process.cwd(), 'src/lib/paraglide/messages');
	if (!fs.existsSync(messageDir) || fs.readdirSync(messageDir).length > 100 || isPROD) {
		await compile({
			project: './project.inlang',
			outdir: './src/lib/paraglide',
			strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
			emitTsDeclarations: true,
			outputStructure: isPROD ? 'message-modules' : 'locale-modules',
			isServer: "import.meta.env?.SSR ?? typeof window === 'undefined'"
		});
	}

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
