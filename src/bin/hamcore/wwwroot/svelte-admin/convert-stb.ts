import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';

const IGNORE: string[] = ['CMD', 'D_SW', 'D_CM', 'D_EM', 'SW'];
const VERSION = '0.2';

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
	const len = line.length;

	if (len == 0) return [null, prefix];
	if (line[0] == '#' || (line[0] == '/' && line[1] == '/')) return [null, prefix];

	let b = false;
	let len_name = 0;
	let i: number;
	for (i = 0; i < line.length; i++) {
		if (line[i] == ' ' || line[i] == '\t') {
			b = true;
			break;
		}
		len_name++;
	}

	if (b == false) return [null, prefix];

	const name = line.substring(0, len_name);

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

function parseTagList(str: string) {
	const list: string[] = [];
	let mode = 0;
	let tmp = '';

	str += '_';

	const len = str.length;

	for (let i = 0; i < len; i++) {
		const c = str[i]!;

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

export async function convertStb() {
	const files = await readdir('../../');
	const regex = /strtable_(.+)\.stb/;

	for (const file of files) {
		if (!file.startsWith('strtable_')) continue;
		const locale = file.match(regex)![1];

		const content = await readFile(join('../../', file), { encoding: 'utf-8' });
		const hash = createHash('sha256').update(content).digest('hex');
		let prefix = '';
		const message: Record<string, string> = {
			$schema: 'https://inlang.com/schema/inlang-message-format',
			$hash: hash,
			$version: VERSION
		};

		const destPath = `./messages/${locale}.json`;
		if (existsSync(destPath)) {
			const destContent = await readFile(destPath, { encoding: 'utf-8' });
			const destJson = JSON.parse(destContent) as Record<string, string>;
			if (destJson['$hash'] == hash && destJson['$version'] == VERSION) continue;
		}

		for (const line of content.split(/\r?\n|\r|\n/g)) {
			const [entry, newPrefix] = parseTableLine(line, prefix);
			prefix = newPrefix;

			if (entry == null) continue;
			if (IGNORE.some((x) => entry.name.startsWith(x))) continue;
			let i = 0;
			for (const tag of entry.tagList) {
				if (tag == '%u' || tag == '%s' || tag == '%S') {
					entry.str = entry.str.replace(tag, `{input${i}}`);
				}
				i++;
			}
			message[entry.name] = entry.str;
		}

		await writeFile(destPath, JSON.stringify(message, null, 2));
		console.log('Converted ' + locale);
	}

	console.log('Finish converting stb table');
}
