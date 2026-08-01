export function isDefaultDate(date: Date | string | number): boolean {
	if (typeof date === 'string') return date == '1970-01-01T09:00:00.000Z';
	else if (typeof date === 'object') date = date.valueOf();
	if (typeof date === 'number') return date == 32400000;
	return false;
}
