import type { Component } from 'svelte';

type Action = () => PromiseLike<unknown>;

export interface ConfirmProps {
	title?: string;
	icon?: Component<{}>;
	message: string;
	resolver: PromiseWithResolvers<void>;
	action: Action;
}

class ConfirmState {
	props = $state<ConfirmProps>();

	confirm(props: Omit<ConfirmProps, 'action' | 'resolver'>, action: Action) {
		let resolver = Promise.withResolvers<void>();
		this.props = { ...props, resolver, action };
		return resolver.promise;
	}

	async resolve(value: boolean) {
		if (this.props == undefined) throw Error();

		if (value) await this.props.action();

		this.props.resolver.resolve();
		this.props = undefined;
	}
}

const instance = new ConfirmState();

export function getState() {
	return instance;
}

export function confirm(props: Omit<ConfirmProps, 'action' | 'resolver'>, action: Action) {
	return instance.confirm(props, action);
}
