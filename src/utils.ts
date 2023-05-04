export function readString(buf: Uint8Array, offset: number = 0): string {
	const strEnd = buf.findIndex((n, i) => n == 0 && i >= offset);
	const strArray = buf.slice(offset, strEnd != -1 ? strEnd : buf.length - 1);
	return [...strArray].map((n) => String.fromCharCode(n)).join('');
}

export function hasFlag(value: number | bigint, flag: number | bigint): boolean {
	return (Number(value) & Number(flag)) == Number(flag);
}

export function bufferAsString(buf: ArrayBufferLike, format: string = 'hex'): string {
	const array = [...new Uint8Array(buf)];
	switch (format) {
		case 'string':
			return array.map((v) => String.fromCharCode(v)).join('');
		case 'hex':
			return array.map((v) => '0x' + v.toString(16)).join(' ');
		default:
			throw new ReferenceError(`Format "${format}" not supported`);
	}
}

export function arrayToTR(array: Array<any>): HTMLTableRowElement {
	const row = document.createElement('tr');
	for (let text of array) {
		const td = document.createElement('td');
		td.innerText = text.toString();
		row.appendChild(td);
	}

	return row;
}
