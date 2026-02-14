/*
	Installed from @ieedan/std
*/

/** Checks if provided value is actually a number.
 *
 * @param num value to check
 * @returns
 *
 * ## Usage
 *
 * ```ts
 * isNumber("2"); // true
 * isNumber("1.11"); // true
 * isNumber("0xff"); // true
 *
 * isNumber("two"); // false
 * isNumber({ two: 2 }); // false
 * isNumber(Number.POSITIVE_INFINITY); // false
 * ```
 */
export function isNumber(num: unknown): boolean {
	if (typeof num === 'number') return num - num === 0;

	if (typeof num === 'string' && num.trim() !== '') return Number.isFinite(+num);

	return false;
}
