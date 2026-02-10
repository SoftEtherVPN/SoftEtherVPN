/*
	Installed from @ieedan/std
*/

/** This is just a helper type used only within this file */
type _Result<T, E> = { ok: true; val: T } | { ok: false; err: E };

/** Result allows you to show to a consumer that a function might throw and force them to handle it.
 *
 *  `T` Value type
 *
 *  `E` Error type
 *
 * ## Usage
 *
 * ```ts
 * function functionThatMightFail(): Result<T, E>;
 * ```
 *
 * ## Usage
 *
 * ```ts
 * const functionThatMightFail = (): Result<string, string> => Ok("Hello, World!");
 *
 * const result = functionThatMightFail();
 *
 * console.log(result.unwrap()); // "Hello, World!"
 * ```
 */
class Result<T, E> {
	private readonly _result: _Result<T, E>;

	constructor(result: _Result<T, E>) {
		this._result = result;
	}

	/** Allows you to run callbacks based on the result.
	 *
	 * @param success callback to be run when result is success
	 * @param failure callback to be run when result is failure
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.match(
	 * 	(val) => val,
	 * 	() => {
	 * 		throw new Error('oops!')
	 * 	}
	 * );
	 * ```
	 *
	 * ## Usage
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello, World!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const val = result.match(
	 * 	(val) => val,
	 * 	() => {
	 * 		throw new Error('oops!')
	 * 	}
	 * );
	 *
	 * console.log(val); // "Hello, World!"
	 * ```
	 */
	match<A, B = A>(success: (val: T) => A, failure: (err: E) => B): A | B {
		if (!this._result.ok) {
			return failure(this._result.err);
		}

		return success(this._result.val);
	}

	/** Maps `Result<T, E>` to `Result<A, E>` using the passed mapping function
	 *
	 * @param fn Mapping function
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.map((val) => val.length);
	 * ```
	 *
	 * ## Usage
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello, World!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const hello = result.map((val) => val.slice(0, 5));
	 *
	 * console.log(hello.unwrap()); // "Hello"
	 * ```
	 */
	map<A>(fn: (val: T) => A): Result<A, E> {
		return this.match(
			(val) => Ok(fn(val)),
			(err) => Err(err)
		);
	}

	/** In the `Ok` case returns the mapped value using the function else returns `defaultVal`
	 *
	 * @param defaultVal Value to be returned when `Err`
	 * @param fn Mapping function to map in case of `Ok`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.mapOr(1, (val) => val.length);
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("foo");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapOr(1, (val) => val.length);
	 *
	 * console.log(length); // 3
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapOr(1, (val) => val.length);
	 *
	 * console.log(length); // 1
	 * ```
	 */
	mapOr<A>(defaultVal: A, fn: (val: T) => A): A {
		return this.match(
			(val) => fn(val),
			(_) => defaultVal
		);
	}

	/** In the `Ok` case returns the mapped value using `fn` else returns value of `def`
	 *
	 * @param def Mapping function called when `Err`
	 * @param fn Mapping function called when `Ok`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.mapOrElse(() => 1, (val) => val.length);
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("foo");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapOrElse(() => 1, (val) => val.length);
	 *
	 * console.log(length); // 3
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapOr(() => 1, (val) => val.length);
	 *
	 * console.log(length); // 1
	 * ```
	 */
	mapOrElse<A>(def: (err: E) => A, fn: (val: T) => A): A {
		return this.match(
			(val) => fn(val),
			(err) => def(err)
		);
	}

	/** Maps `Result<T, E>` to `Result<T, A>` using the passed mapping function
	 *
	 * @param fn Mapping function
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.mapErr((err) => getCodeMsg(err));
	 * ```
	 *
	 * ## Usage
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err(10);
	 *
	 * const result = functionThatMightFail();
	 *
	 * const message = result.mapErr(() => "Error");
	 *
	 * console.log(message); // "Error"
	 * ```
	 */
	mapErr<A>(fn: (err: E) => A): Result<T, A> {
		return this.match(
			(val) => Ok(val),
			(err) => Err(fn(err))
		);
	}

	/** In the `Err` case returns the mapped value using the function else returns `defaultVal`
	 *
	 * @param defaultVal Value to be returned when `Ok`
	 * @param fn Mapping function to map in case of `Err`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.mapErrOr("Should've been error", (err) => getCodeMsg(err));
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("foo");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const message = result.mapErrOr("Should've been error", () => "Error");
	 *
	 * console.log(message); // "Should've been error"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err(10);
	 *
	 * const result = functionThatMightFail();
	 *
	 * const message = result.mapErrOr("Should've been error", () => "Error");
	 *
	 * console.log(message); // "Error"
	 * ```
	 */
	mapErrOr<A>(defaultVal: A, fn: (err: E) => A): A {
		return this.match(
			(_) => defaultVal,
			(err) => fn(err)
		);
	}

	/** In the `Err` case returns the mapped value using the function else returns value of `def`
	 *
	 * @param def Mapping function called when `Ok`
	 * @param fn Mapping function called when `Err`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.mapErrOrElse(() => "Value", (_) => "Error!");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("foo");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapErrOrElse(() => 1, (val) => val.length);
	 *
	 * console.log(length); // 1
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * const length = result.mapOr(() => 1, (val) => val.length);
	 *
	 * console.log(length); // 4
	 * ```
	 */
	mapErrOrElse<A>(def: (val: T) => A, fn: (err: E) => A): A {
		return this.match(
			(val) => def(val),
			(err) => fn(err)
		);
	}

	/** Returns true if result is `Ok`
	 *
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.isOk();
	 * ```
	 */
	isOk(): boolean {
		return this.match(
			() => true,
			() => false
		);
	}

	/** Returns true if result is `Err`
	 *
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.isErr();
	 * ```
	 */
	isErr(): boolean {
		return this.match(
			() => false,
			() => true
		);
	}

	/** Tries to return value if value is `Err` throws generic error message.
	 *
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrap();
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrap()); // "Hello!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * result.unwrap(); // Error: Attempted to call `.unwrap()` on a non `Ok` value.
	 * ```
	 */
	unwrap(): T {
		return this.match(
			(val) => val,
			() => {
				throw new Error('Attempted to call `.unwrap()` on a non `Ok` value.');
			}
		);
	}

	/** Tries to return err if value is `Ok` throws generic error message.
	 *
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrapErr();
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * result.unwrapErr(); // Error: Attempted to call `.unwrapErr()` on a non `Err` value.
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapErr()); // "oops!"
	 * ```
	 */
	unwrapErr(): E {
		return this.match(
			() => {
				throw new Error('Attempted to call `.unwrapErr()` on a non `Err` value.');
			},
			(err) => err
		);
	}

	/** Tries to unwrap the value if value is `Err` returns `defaultVal`
	 *
	 * @param defaultVal Value to be returned if `Err`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrapOr(7);
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapOr("Yellow!")); // "Hello!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapOr("Yellow!")); // "Yellow!"
	 * ```
	 */
	unwrapOr(defaultVal: T): T {
		return this.match(
			(val) => val,
			(_) => defaultVal
		);
	}

	/** Tries to unwrap the error if vale is `Ok` returns `defaultVal`
	 *
	 * @param defaultVal
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrapErrOr("Error");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapErrOr("Yellow!")); // "Yellow!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapErrOr("Yellow!")); // "oops!"
	 * ```
	 */
	unwrapErrOr(defaultVal: E): E {
		return this.match(
			() => defaultVal,
			(err) => err
		);
	}

	/** Tries to return the value if value is `Err` calls `fn`
	 *
	 * @param fn Function called if `Err`
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrapOrElse(() => "Hello!");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapOrElse(() => "oops!")); // "Hello!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapOrElse(() => "Hello!")); // "Hello!"
	 * ```
	 *
	 */
	unwrapOrElse(fn: (err: E) => T): T {
		return this.match(
			(val) => val,
			(err) => fn(err)
		);
	}

	/** Tries to return the error if value is `Ok` calls `fn`
	 *
	 * @param fn Function called if `Ok`
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.unwrapErrOrElse(() => "Error!");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapErrOrElse(() => "oops!")); // "oops!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.unwrapErrOrElse(() => "Hello!")); // "oops!"
	 * ```
	 *
	 */
	unwrapErrOrElse(fn: (val: T) => E): E {
		return this.match(
			(val) => fn(val),
			(err) => err
		);
	}

	/** Tries to return value if value is `Err` throws custom error message.
	 *
	 * @param message Message to show when value is `Err`
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.expect("Custom message");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.expect("I failed!")); // "Hello!"
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * result.expect("I failed!"); // Error: I failed!
	 * ```
	 */
	expect(message: string): T {
		return this.match(
			(val) => val,
			() => {
				throw new Error(message);
			}
		);
	}

	/** Tries to return error value if value is `Ok` throws custom error message
	 *
	 * @param message
	 * @returns
	 *
	 * ## Usage
	 *
	 * ```ts
	 * result.expectErr("Custom message");
	 * ```
	 *
	 * ## Usage
	 *
	 * ### When `Ok`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Ok("Hello!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.expectErr("I failed!")); // Error: I failed!
	 * ```
	 *
	 * ### When `Err`
	 *
	 * ```ts
	 * const functionThatMightFail = (): Result<string, string> => Err("oops!");
	 *
	 * const result = functionThatMightFail();
	 *
	 * console.log(result.expectErr("I failed!")); // "oops!"
	 * ```
	 */
	expectErr(message: string): E {
		return this.match(
			() => {
				throw new Error(message);
			},
			(err) => err
		);
	}
}

/** Returns a new `Ok` result type with the provided value
 *
 * @param val Value of the result
 * @returns
 *
 * ## Usage
 *
 * ```ts
 * Ok(true);
 * ```
 *
 * ## Usage
 *
 * ```ts
 * const functionThatCanFail = (condition) => {
 * 	if (condition) {
 * 		Ok("Success")
 * 	}
 *
 * 	return Err("Failure");
 * }
 * ```
 */
export function Ok<T>(val: T): Result<T, never> {
	return new Result<T, never>({ ok: true, val });
}

/** Returns a new `Err` result type with the provided error
 *
 * @param err Error of the result
 * @returns
 *
 * ## Usage
 *
 * ```ts
 * Err("I failed!");
 * ```
 *
 * ## Usage
 *
 * ```ts
 * const functionThatCanFail = (condition) => {
 * 	if (condition) {
 * 		Ok("Success")
 * 	}
 *
 * 	return Err("Failure");
 * }
 * ```
 */
export function Err<E>(err: E): Result<never, E> {
	return new Result<never, E>({ ok: false, err });
}

export type { Result };
