export type IPv4AddressInputProps = {
	separator?: '.' | ' ' | '_';
	/** An IP Address placeholder `0.0.0.0` or `0_0_0_0` or `0 0 0 0` */
	placeholder?: string;
	value?: string | null;
	class?: string;
	valid?: boolean;
	name?: string;
};

export type IPv4AddressInputPropsWithoutHTML = IPv4AddressInputProps;
