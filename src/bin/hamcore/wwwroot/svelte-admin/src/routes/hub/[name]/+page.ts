import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import type { PageLoad } from './$types';

// The hub root has no content of its own yet: land on the user list, which is
// the first entry of the hub menu. Drop this once a hub status page exists.
export const load: PageLoad = ({ params }) => {
	redirect(307, resolve('/hub/[name]/users', { name: params.name }));
};
