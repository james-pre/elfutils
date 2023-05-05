import { Buffer } from 'buffer';

export function readString(buf: Buffer, offset: number = 0): string {
	const end = buf.findIndex((n, i) => n == 0 && i >= offset);
	return buf.slice(offset, end != -1 ? end : buf.length - 1).toString();
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
