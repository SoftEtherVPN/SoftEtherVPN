import { compile } from '@inlang/paraglide-js';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

await compile({
	project: './project.inlang',
	outdir: './src/lib/paraglide',
	strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
	emitTsDeclarations: true
});

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/api': {
				target: import.meta.env.RPC_SERVER_URL,
				changeOrigin: true,
				secure: false
			}
		}
	}
});
