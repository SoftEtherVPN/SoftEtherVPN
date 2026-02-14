import type {
	BundleImport,
	Declaration,
	InlangPlugin,
	MessageImport,
	VariantImport
} from '@inlang/sdk';

const plugin: InlangPlugin = {
	key: 'plugin.softether.stb',
	toBeImportedFiles: async ({ settings }) => {
		return settings.locales.map((locale) => ({
			locale,
			path: `../../strtable_${locale}.stb`
		}));
	},
	importFiles: async ({ files }) => {
		const bundles: BundleImport[] = [];
		const messages: MessageImport[] = [];
		const variants: VariantImport[] = [];

		for (const file of files) {
			const content = new TextDecoder().decode(file.content);
			let prefix = '';

			for (let line of content.split(/\r?\n|\r|\n/g)) {
				let [entry, newPrefix] = parseTableLine(line, prefix);
				prefix = newPrefix;

				if (entry != null) {
					//if (entry.tagList.length != 0) console.log(entry.tagList);

					let declarations: Declaration[] = entry.tagList
						.map((tag, i) => {
							if (tag == '%u' || tag == '%s' || tag == '%S') {
								let ext = tag == '%u' ? ': number' : '';
								entry.str = entry.str.replace(tag, `{{input${i}${ext}}}`);
								return {
									name: 'input' + i,
									type: 'input-variable'
								} as Declaration;
							}
							return null;
						})
						.filter((d) => d != null);

					bundles.push({
						id: entry.name,
						declarations
					});

					messages.push({
						bundleId: entry.name,
						locale: file.locale
					});

					variants.push({
						messageBundleId: entry.name,
						messageLocale: file.locale,
						pattern: buildPattern(entry.str)
					});
				}
			}
		}

		return { bundles, messages, variants };
	},
	exportFiles: async () => []
};

function buildPattern(str: string): VariantImport['pattern'] {
	const pattern: VariantImport['pattern'] = [];
	const regex = /\{\{(\w+)(?::\s*\w+)?\}\}/g;
	let lastIndex = 0;
	let match: RegExpExecArray | null;

	while ((match = regex.exec(str)) !== null) {
		if (match.index > lastIndex) {
			pattern.push({ type: 'text', value: str.slice(lastIndex, match.index) });
		}

		pattern.push({
			type: 'expression',
			arg: { type: 'variable-reference', name: match[1] }
		});

		lastIndex = regex.lastIndex;
	}

	if (lastIndex < str.length) {
		pattern.push({ type: 'text', value: str.slice(lastIndex) });
	}

	return pattern;
}

export default plugin;

interface StbTable {
	name: string;
	str: string;
	tagList: string[];
}

function unescapeStr(str: string) {
	let tmp = '';
	for (let i = 0; i < str.length; i++) {
		if (str[i] == '\\') {
			i++;
			switch (str[i]) {
				case '\\':
					tmp += '\\';
					break;
				case ' ':
					tmp += ' ';
					break;
				case 'n':
				case 'N':
					tmp += '\n';
					break;
				case 'r':
				case 'R':
					tmp += '\r';
					break;
				case 't':
				case 'T':
					tmp += '\t';
					break;
			}
		} else if (str[i] == '&') {
			i++;
			if (str[i] == '&') {
				tmp += '&';
			} else tmp += str[i];
		} else tmp += str[i];
	}

	return tmp;
}

function parseTableLine(line: string, prefix: string): [StbTable | null, string] {
	line = line.trimStart();
	let len = line.length;

	if (len == 0) return [null, prefix];
	if (line[0] == '#' || (line[0] == '/' && line[1] == '/')) return [null, prefix];

	let b = false;
	let len_name = 0;
	for (var i = 0; i < line.length; i++) {
		if (line[i] == ' ' || line[i] == '\t') {
			b = true;
			break;
		}
		len_name++;
	}

	if (b == false) return [null, prefix];

	let name = line.substring(0, len_name);

	let string_start = len_name;
	for (i = len_name; i < len; i++) {
		if (line[i] != ' ' && line[i] != '\t') break;
		string_start++;
	}

	if (i == len) return [null, prefix];

	let str = line.substring(string_start);
	str = unescapeStr(str);

	if (name.toUpperCase() == 'PREFIX') {
		prefix = str;
		prefix = prefix.trimStart();

		if (prefix == '$' || prefix.toUpperCase() == 'NULL') prefix = '';

		return [null, prefix];
	}

	let name2 = '';

	if (prefix != '') {
		//js dont like @
		name2 += prefix + '__';
	}

	name2 += name;

	return [
		{
			name: name2,
			str,
			tagList: parseTagList(str)
		},
		prefix
	];
}

function compareTagList(list1: string[], list2: string[]) {
	if (list1.length != list2.length) return false;

	for (let i = 0; i < list1.length; i++) {
		if (list1[i] != list2[i]) return false;
	}

	return true;
}

function parseTagList(str: string) {
	let list: string[] = [];
	let mode = 0;
	let tmp = '';

	str += '_';

	let len = str.length;

	for (let i = 0; i < len; i++) {
		let c = str[i];

		if (mode == 0) {
			switch (c) {
				case '%':
					if (str[i + 1] == '%') {
						i++;
						tmp += c;
					} else {
						mode = 1;
						tmp = c;
					}
					break;
				default:
					tmp = c;
					break;
			}
		} else {
			switch (c) {
				case 'c':
				case 'C':
				case 'd':
				case 'i':
				case 'o':
				case 'u':
				case 'x':
				case 'X':
				case 'e':
				case 'E':
				case 'f':
				case 'g':
				case 'G':
				case 'n':
				case 'N':
				case 's':
				case 'S':
				case 'r':
				case ' ':
					tmp += c;
					list.push(tmp);
					mode = 0;
					break;
				default:
					tmp += c;
					break;
			}
		}
	}

	return list;
}
