import { readFile, open, FileHandle, writeFile } from 'node:fs/promises';

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

const IGNORE: string[] = ['CMD', 'D_SW', 'D_CM', 'D_EM', 'SW'];

const content = await readFile('../../strtable_en.stb', { encoding: 'utf8' });
const indexFile = await open('index.trad.txt', 'w+');

let prefixes: string[] = [];
let prefix = '';
for (let line of content.split(/\r?\n|\r|\n/g)) {
	let [entry, newPrefix] = parseTableLine(line, prefix);
	prefix = newPrefix;

	if (!prefixes.includes(prefix)) prefixes.push(prefix);

	if (entry != null) {
		if (IGNORE.some((x) => entry.name.startsWith(x))) continue;
		await indexFile.write(`${entry.name}   ${entry.str}\n`);
	}
}
await writeFile('index.json', JSON.stringify(prefixes), { flag: 'w+', encoding: 'utf8' });
await indexFile.close();
