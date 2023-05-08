import { ELF } from '../index';
export * from '../index';

let files: File[] = [];

const std = {
	get out() {
		return document.querySelector<HTMLPreElement>('#stdout').innerText;
	},
	set out(val) {
		document.querySelector<HTMLPreElement>('#stdout').innerText = val;
	},
	get err() {
		return document.querySelector<HTMLPreElement>('#stderr').innerText;
	},
	set err(val) {
		document.querySelector<HTMLPreElement>('#stderr').innerText = val;
	},
};

const file_input = document.querySelector<HTMLInputElement>('#file-input');
file_input.onchange = evt => {
	files = Array.from(file_input.files);
};

export let elf: ELF;
document.querySelector<HTMLButtonElement>('#parse').onclick = async evt => {
	if (!files.length) {
		std.err = 'No file[s] selected';
		return;
	}

	const raw = await files[0].arrayBuffer();
	elf = await ELF.FromBuffer(raw);
	const html = elf.toHTML();

	document.querySelector('#header').innerHTML = '';
	document.querySelector('#header').append(html);
};
