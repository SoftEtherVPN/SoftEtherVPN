export type Language = {
	/** Language code (e.g., 'en', 'de') */
	code: string;
	/** Display name (e.g., 'English', 'Deutsch') */
	label: string;
};

export type LanguageSwitcherProps = {
	/** List of available languages */
	languages: Language[];

	/** Current selected language code */
	value?: string;

	/** Dropdown alignment */
	align?: 'start' | 'center' | 'end';

	/** Button variant */
	variant?: 'outline' | 'ghost';

	/** Called when the language changes */
	onChange?: (code: string) => void;

	class?: string;
};
