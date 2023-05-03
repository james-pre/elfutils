import { e_ident, e_type, e_machine, e_machine_strings, p_type, sh_type, EI_OSABI_STRINGS, sh_flags, st_type, st_bindings, st_visibility, p_flags, d_tag } from './constants';
import { bufferAsString, hasFlag, readString, arrayToTR } from './utils';

export interface DecodeOptions {
	isLE: boolean;
	is32bit: boolean;
}

export interface ELFElement {
	toString(elf?: ELF): string;
	toHTML(elf?: ELF): HTMLElement;
}

export interface ELFElementStatic {
	SH_TYPES: sh_type[];
	FromBuffer(buffer: ArrayBufferLike, options?: DecodeOptions): ELFElement;
}

export class ELFHeader implements ELFElement {
	public constructor(
		public ident: { [key in e_ident]: number },
		public type: e_type,
		public machine: e_machine,
		public version: number,
		public entry: number | bigint,
		public phoff: number | bigint,
		public shoff: number | bigint,
		public flags: number,
		public ehsize: number,
		public phentsize: number,
		public phnum: number,
		public shentsize: number,
		public shnum: number,
		public shstrndx: number
	) {}

	public static FromBuffer(buffer: ArrayBufferLike): ELFHeader {
		const view = new DataView(buffer),
			EI_CLASS = view.getUint8(4),
			EI_DATA = view.getUint8(5);
		return new ELFHeader(
			{
				[e_ident.MAG0]: view.getUint8(0),
				[e_ident.MAG1]: view.getUint8(1),
				[e_ident.MAG2]: view.getUint8(2),
				[e_ident.MAG3]: view.getUint8(3),
				[e_ident.CLASS]: EI_CLASS,
				[e_ident.DATA]: EI_DATA,
				[e_ident.VERSION]: view.getUint8(6),
				[e_ident.OSABI]: view.getUint8(7),
				[e_ident.ABIVERSION]: view.getUint8(8),
			}, // e_ident
			view.getUint16(0x10, EI_DATA == 1), // e_type
			view.getUint16(0x12, EI_DATA == 1), // e_machine
			view.getUint32(0x14, EI_DATA == 1), // e_version
			EI_CLASS == 1 ? view.getUint32(0x18, EI_DATA == 1) : view.getBigUint64(0x18, EI_DATA == 1), // e_entry
			EI_CLASS == 1 ? view.getUint32(0x1c, EI_DATA == 1) : view.getBigUint64(0x20, EI_DATA == 1), // e_phoff
			EI_CLASS == 1 ? view.getUint32(0x20, EI_DATA == 1) : view.getBigUint64(0x28, EI_DATA == 1), // e_shoff
			view.getUint32(EI_CLASS == 1 ? 0x24 : 0x30, EI_DATA == 1), // e_flags
			view.getUint16(EI_CLASS == 1 ? 0x28 : 0x34, EI_DATA == 1), // e_ehsize
			view.getUint16(EI_CLASS == 1 ? 0x2a : 0x36, EI_DATA == 1), // e_phentsize
			view.getUint16(EI_CLASS == 1 ? 0x2c : 0x38, EI_DATA == 1), // e_phnum
			view.getUint16(EI_CLASS == 1 ? 0x2e : 0x3a, EI_DATA == 1), // e_shentsize
			view.getUint16(EI_CLASS == 1 ? 0x30 : 0x3c, EI_DATA == 1), // e_shnum
			view.getUint16(EI_CLASS == 1 ? 0x32 : 0x3e, EI_DATA == 1) // e_shstrndx
		);
	}

	public toString(): string {
		return `\
		Magic: 0x${this.ident[e_ident.MAG0].toString(16)} \
		${String.fromCharCode(this.ident[e_ident.MAG1])} \
		${String.fromCharCode(this.ident[e_ident.MAG2])} \
		${String.fromCharCode(this.ident[e_ident.MAG3])}
		Class: ${this.ident[e_ident.CLASS] == 1 ? 'ELF32' : 'ELF64'}
		Endianness: ${this.ident[e_ident.DATA] == 1 ? 'Little Endian' : 'Big Endian'}
		Version: ${this.ident[e_ident.VERSION]}
		OS/ABI: ${EI_OSABI_STRINGS[this.ident[e_ident.OSABI]]}
		ABI version: ${this.ident[e_ident.ABIVERSION]}
		Type: ${e_type[this.type]}
		Machine: ${e_machine_strings[this.machine] || '0x' + this.machine.toString(16)}
		Version: 0x${this.version.toString(16)}
		Entry point: 0x${this.entry.toString(16)}
		Start of program headers: ${this.phoff} (bytes into file)
		Start of section headers: ${this.shoff} (bytes into file)
		Flags: 0x${this.flags.toString(16)}
		Header size: ${this.ehsize} (bytes)
		Program header entry size: ${this.phentsize} (bytes)
		Program header entries: ${this.phnum}
		Section header table entry size: ${this.shentsize} (bytes)
		Section header table entries: ${this.shnum}
		Section header table names index: ${this.shstrndx}`.replaceAll('\t', '');
	}

	public toHTML(): HTMLPreElement {
		const text = this.toString();
		const element = document.createElement('pre');
		element.innerHTML = text.replaceAll('\n', '<br>');
		return element;
	}
}

export class ProgramHeader implements ELFElement {
	public constructor(
		public options: DecodeOptions,
		public type: p_type,
		public flags: number,
		public offset: number | bigint,
		public vaddr: number | bigint,
		public paddr: number | bigint,
		public filesz: number | bigint,
		public memsz: number | bigint,
		public align: number | bigint
	) {}

	public toString(elf: ELF): string {
		return `\
				Type: ${p_type[this.type] || '0x' + this.type.toString(16)}
				Offset: ${this.offset} (bytes)
				Virtual address: 0x${this.vaddr.toString(16)}
				Physical address: 0x${this.paddr.toString(16)}
				File segment size: ${this.filesz} (bytes)
				Memory segment size: ${this.memsz} (bytes)
				Flags: ${Object.entries(p_flags)
					.map(([text, num]) => (hasFlag(this.flags, Number(num)) ? text : ''))
					.filter((flag) => flag)
					.join(', ')}
				Alignment: ${this.align}${this.type == p_type.INTERP ? `\n[Requesting interpreter: ${bufferAsString(elf.getProgramHeaderValue(this), 'string')}]` : ''}
			`.replaceAll('\t', '');
	}

	public toHTML(elf: ELF): HTMLTableRowElement {
		return arrayToTR([
			`${p_type[this.type] || '0x' + this.type.toString(16)}`,
			this.offset,
			`0x${this.vaddr.toString(16)}`,
			`0x${this.paddr.toString(16)}`,
			this.filesz,
			this.memsz,
			Object.entries(p_flags)
				.map(([text, num]) => (hasFlag(this.flags, Number(num)) ? text : ''))
				.filter((flag) => flag)
				.join(', '),
			this.align,
		]);
	}

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['Type', 'Offset', 'Virtual Address', 'Physical Address', 'File size', 'Memory size', 'Flags', 'Alignment']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions): ProgramHeader {
		const view = new DataView(buffer);

		return new ProgramHeader(
			options,
			view.getUint32(0, options.isLE), // p_type
			view.getUint32(options.is32bit ? 0x18 : 4, options.isLE), // p_flags
			options.is32bit ? view.getUint32(4, options.isLE) : view.getBigUint64(8, options.isLE), // p_offset
			options.is32bit ? view.getUint32(8, options.isLE) : view.getBigUint64(0x10, options.isLE), // p_vaddr
			options.is32bit ? view.getUint32(0x0c, options.isLE) : view.getBigUint64(0x18, options.isLE), // p_paddr
			options.is32bit ? view.getUint32(0x10, options.isLE) : view.getBigUint64(0x20, options.isLE), // p_filesz
			options.is32bit ? view.getUint32(0x14, options.isLE) : view.getBigUint64(0x28, options.isLE), // p_memsz
			options.is32bit ? view.getUint32(0x1c, options.isLE) : view.getBigUint64(0x30, options.isLE) // p_align
		);
	}
}

export class SectionHeader implements ELFElement {
	public constructor(
		public options: DecodeOptions,
		public name: number,
		public type: sh_type,
		public flags: number | bigint,
		public addr: number | bigint,
		public offset: number | bigint,
		public size: number | bigint,
		public link: number,
		public info: number,
		public addralign: number | bigint,
		public entsize: number | bigint
	) {}

	public getName(elf: ELF): string {
		return readString(elf.getSectionHeaderValue(elf.sectionHeaders[elf.header.shstrndx]), this.name);
	}

	public getData(elf: ELF, t: ELFElementStatic): ELFElement[] {
		const valuesBuffer = elf.getSectionHeaderValue(this).buffer,
			result = [];

		if (!t.SH_TYPES.includes(this.type)) {
			throw new TypeError(`Invalid type`);
		}

		for (let i = 0; i < this.size; i += Number(this.entsize)) {
			const entBuffer = valuesBuffer.slice(i, i + Number(this.entsize));
			const ent = t.FromBuffer(entBuffer, this.options);
			result.push(ent);
		}

		return result;
	}

	public toString(elf: ELF): string {
		return `\
				[${elf?.sectionHeaders?.indexOf(this)}] \
				Name: ${this.getName(elf) || `Unknown (at 0x${this.name.toString(16)})`}
				Type: ${sh_type[this.type] || '0x' + this.type.toString(16)}
				Address: 0x${this.addr.toString(16)}
				Flags: ${Object.entries(sh_flags)
					.map(([text, num]) => (hasFlag(this.flags, Number(num)) ? text : ''))
					.filter((flag) => flag)
					.join(', ')}
				Offset: ${this.offset} (bytes)
				Size: ${this.size} (bytes)
				Link: ${this.link}
				Info: ${this.info}
				Address alignment: ${this.addralign}
				Entry size: ${this.entsize}
			`.replaceAll('\t', '');
	}

	public toHTML(elf: ELF): HTMLTableRowElement {
		return arrayToTR([
			elf.sectionHeaders.indexOf(this),
			this.getName(elf) || `Unknown (at 0x${this.name.toString(16)})`,
			`${sh_type[this.type] || '0x' + this.type.toString(16)}`,
			`0x${this.addr.toString(16)}`,
			Object.entries(sh_flags)
				.map(([text, num]) => (hasFlag(this.flags, Number(num)) ? text : ''))
				.filter((flag) => flag)
				.join(', '),
			this.offset,
			this.size,
			this.link,
			this.info,
			this.addralign,
			this.entsize,
		]);
	}

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['No.', 'Name', 'Type', 'Address', 'Flags', 'Offset', 'Size', 'Link', 'Info', 'Align', 'Entry size']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions): SectionHeader {
		const view = new DataView(buffer);
		return new SectionHeader(
			options,
			view.getUint32(0, options.isLE), // sh_name
			view.getUint32(4, options.isLE), // sh_type
			options.is32bit ? view.getUint32(8, options.isLE) : view.getBigUint64(8, options.isLE), // sh_flags
			options.is32bit ? view.getUint32(0x0c, options.isLE) : view.getBigUint64(0x10, options.isLE), // sh_addr
			options.is32bit ? view.getUint32(0x10, options.isLE) : view.getBigUint64(0x18, options.isLE), // sh_offset
			options.is32bit ? view.getUint32(0x14, options.isLE) : view.getBigUint64(0x20, options.isLE), // sh_size
			view.getUint32(options.is32bit ? 0x18 : 0x28, options.isLE), // sh_link
			view.getUint32(options.is32bit ? 0x1c : 0x2c, options.isLE), // sh_info
			options.is32bit ? view.getUint32(0x20, options.isLE) : view.getBigUint64(0x30, options.isLE), // sh_addralign
			options.is32bit ? view.getUint32(0x24, options.isLE) : view.getBigUint64(0x38, options.isLE) // sh_entsize
		);
	}
}

export class Symbol implements ELFElement {
	public constructor(
		public options: DecodeOptions,
		public name: number,
		public value: number | bigint,
		public size: number | bigint,
		public info: number,
		public other: number,
		public shndx: number
	) {}

	public toString(elf?: ELF): string {
		const strtab = elf && elf.getSectionHeaderByName('.strtab');
		const names = strtab && elf.getSectionHeaderValue(strtab);
		return `\
		Name: ${names ? readString(names, this.name) : `Unknown (at 0x${this.name.toString(16)})`}
		Type: ${st_type[this.info & 0xf]}
		Bind: ${st_bindings[this.info >> 4]}
		Visibility: ${st_visibility[this.other]}
		Size: ${this.size}
		Index: ${this.shndx == 0xfff1 ? 'ABS' : this.shndx}
		Value: 0x${this.value.toString(16)}
		`.replaceAll('\t', '');
	}

	public toHTML(elf?: ELF): HTMLTableRowElement {
		const strtab = elf && elf.getSectionHeaderByName('.strtab');
		const names = strtab && elf.getSectionHeaderValue(strtab);

		return arrayToTR([
			'0x' + this.value.toString(16),
			st_type[this.info & 0xf],
			st_bindings[this.info >> 4],
			st_visibility[this.other],
			this.size,
			this.shndx == 0xfff1 ? 'ABS' : this.shndx,
			names ? readString(names, this.name) : `Unknown (at 0x${this.name.toString(16)})`,
		]);
	}

	public static SH_TYPES: sh_type[] = [sh_type.SYMTAB, sh_type.DYNSYM];

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['Value', 'Type', 'Bind', 'Visibility', 'Size', 'Index', 'Name']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions): Symbol {
		const view = new DataView(buffer);

		return new Symbol(
			options,
			view.getUint32(0, options.isLE), // st_name
			options.is32bit ? view.getUint32(4, options.isLE) : view.getBigUint64(8, options.isLE), // st_value
			options.is32bit ? view.getUint32(8, options.isLE) : view.getBigUint64(16, options.isLE), // st_size
			view.getUint8(options.is32bit ? 12 : 4), // st_info
			view.getUint8(options.is32bit ? 13 : 5), // st_other
			view.getUint16(options.is32bit ? 14 : 6, options.isLE) // st_shndx
		);
	}
}

export class Rel implements ELFElement {
	public constructor(public options: DecodeOptions, public offset: number | bigint, public info: number | bigint, public added?: number | bigint) {}

	public toString(): string {
		return `\
		Offset: 0x${this.offset.toString(16)}
		Info: 0x${this.offset.toString(16)}
		`.replaceAll('\t', '');
	}

	public toHTML(elf?: ELF): HTMLTableRowElement {
		return arrayToTR(['0x' + this.offset.toString(), 'ox' + this.info.toString()]);
	}

	public static SH_TYPES: sh_type[] = [sh_type.REL, sh_type.RELA];

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['Offset', 'Info']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions, needsAddend: boolean): Rel {
		const view = new DataView(buffer);

		return new Rel(
			options,
			options.is32bit ? view.getUint32(0, options.isLE) : view.getBigUint64(0, options.isLE), // r_offset
			options.is32bit ? view.getUint32(4, options.isLE) : view.getBigUint64(8, options.isLE), // r_info
			needsAddend && (options.is32bit ? view.getUint32(8, options.isLE) : view.getBigUint64(16, options.isLE)) // r_addend
		);
	}
}

export class Dyn implements ELFElement {
	public constructor(public options: DecodeOptions, public tag: number | bigint, public val: number | bigint) {}

	public get ptr(): number | bigint {
		return this.val;
	}

	public toString(): string {
		return `\
		Tag: 0x${this.tag.toString(16)}
		Type: ${d_tag[Number(this.tag)]}
		Value: 0x${this.val.toString(16)}
		`.replaceAll('\t', '');
	}

	public toHTML(elf?: ELF): HTMLTableRowElement {
		return arrayToTR(['0x' + this.tag.toString(16), d_tag[Number(this.tag)], '0x' + this.val.toString(16)]);
	}

	public static SH_TYPES: sh_type[] = [sh_type.DYNAMIC];

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['Tag', 'Type', 'Value']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions): Dyn {
		const view = new DataView(buffer);

		return new Dyn(
			options,
			options.is32bit ? view.getUint32(0, options.isLE) : view.getBigUint64(0, options.isLE), // d_tag
			options.is32bit ? view.getUint32(4, options.isLE) : view.getBigUint64(8, options.isLE) // d_val / d_ptr
		);
	}
}

export class Note implements ELFElement {
	public constructor(public options: DecodeOptions, public namesz: number | bigint, public descsz: number | bigint, public type: number | bigint) {}

	public toString(): string {
		return `\
		Name size: ${this.namesz}
		Desc size: ${this.descsz}
		`.replaceAll('\t', '');
	}

	public toHTML(elf?: ELF): HTMLTableRowElement {
		return arrayToTR([this.namesz, this.descsz]);
	}

	public static SH_TYPES: sh_type[] = [sh_type.NOTE];

	public static GetHTMLNameRow(): HTMLTableRowElement {
		return arrayToTR(['Name size', 'Desc size']);
	}

	public static FromBuffer(buffer: ArrayBufferLike, options: DecodeOptions): Note {
		const view = new DataView(buffer);

		return new Note(
			options,
			options.is32bit ? view.getUint32(0, options.isLE) : view.getBigUint64(0, options.isLE), // n_namesz
			options.is32bit ? view.getUint32(4, options.isLE) : view.getBigUint64(8, options.isLE), // n_descsz
			options.is32bit ? view.getUint32(8, options.isLE) : view.getBigUint64(16, options.isLE) // n_type
		);
	}
}

export class ELF {
	public constructor(public buffer: ArrayBufferLike, public header: ELFHeader, public sectionHeaders: SectionHeader[], public programHeaders: ProgramHeader[]) {}

	public static FromBuffer(buffer: ArrayBufferLike) {
		const header = ELFHeader.FromBuffer(buffer);

		const options = { isLE: header.ident[e_ident.DATA] == 1, is32bit: header.ident[e_ident.CLASS] == 1 };
		const sectionHeaders = [];

		for (let i = Number(header.shoff); i < Number(header.shoff) + header.shnum * header.shentsize; i += header.shentsize) {
			const shRaw = buffer.slice(i, i + header.shentsize);
			const sh = SectionHeader.FromBuffer(shRaw, options);
			sectionHeaders.push(sh);
		}

		const programHeaders = [];

		for (let i = 0; i < header.phnum; i++) {
			const phRaw = buffer.slice(Number(header.phoff) + i * header.phentsize, Number(header.phoff) + (i + 1) * header.phentsize);
			const ph = ProgramHeader.FromBuffer(phRaw, options);
			programHeaders.push(ph);
		}

		return new ELF(buffer, header, sectionHeaders, programHeaders);
	}

	public getProgramHeaderValue(header: ProgramHeader): Uint8Array {
		return new Uint8Array(this.buffer.slice(Number(header.offset), Number(header.offset) + Number(header.filesz)));
	}

	public getSectionHeaderValue(header: SectionHeader): Uint8Array {
		return new Uint8Array(this.buffer.slice(Number(header.offset), Number(header.offset) + Number(header.size)));
	}

	public getSectionHeaderByName(name: string): SectionHeader {
		const names = this.getSectionHeaderValue(this.sectionHeaders[this.header.shstrndx]);
		return this.sectionHeaders.find((sh) => readString(names, sh.name) == name);
	}

	public getSectionHeadersByType(type: sh_type): SectionHeader[] {
		return this.sectionHeaders.filter((sh) => sh.type == type);
	}

	public getSymbols(): { sh: SectionHeader; symbols: Symbol[] }[] {
		const result = [];
		for (let sh of this.getSectionHeadersByType(sh_type.SYMTAB)) {
			result.push({ sh, symbols: sh.getData(this, Symbol) });
		}

		return result;
	}

	public getDynamic(): { sh: SectionHeader; dynamic: Dyn[] }[] {
		const result = [];
		for (let sh of this.getSectionHeadersByType(sh_type.DYNAMIC)) {
			result.push({ sh, dynamic: sh.getData(this, Dyn) });
		}

		return result;
	}

	public toString(): string {
		const _symbols = this.getSymbols();
		return `
			${this.header.toString()}

			Section Headers:
			${this.sectionHeaders.map((sh) => sh.toString(this)).join('\n')}

			Program Headers:
			${this.programHeaders.map((ph) => ph.toString(this)).join('\n')}

			${_symbols.map(({ sh, symbols }) => `Symbol table "${sh.getName(this)}" has ${symbols.length} entries: \n${symbols.map((s) => s.toString()).join('\n')}`).join('\n')}
		`.replaceAll('\t', '');
	}

	public toHTML(): HTMLDivElement {
		const container = document.createElement('div');

		container.append(this.header.toHTML());
		container.append(document.createElement('br'));

		const shHeading = document.createElement('pre');
		shHeading.innerText = 'Section Headers:';
		container.append(shHeading);
		const shTable = document.createElement('table');
		shTable.append(SectionHeader.GetHTMLNameRow());
		for (let sh of this.sectionHeaders) {
			shTable.append(sh.toHTML(this));
		}
		container.append(shTable);

		const phHeading = document.createElement('pre');
		phHeading.innerText = 'Program Headers:';
		container.append(phHeading);
		const phTable = document.createElement('table');
		phTable.append(ProgramHeader.GetHTMLNameRow());
		for (let ph of this.programHeaders) {
			phTable.append(ph.toHTML(this));

			if (ph.type == p_type.INTERP) {
				const row = document.createElement('tr');
				const cell = document.createElement('td');
				const interp = document.createElement('div');
				interp.innerHTML = '&nbsp'.repeat(4) + `[Requesting program interpreter: ${bufferAsString(this.getProgramHeaderValue(ph), 'string')}]`;
				interp.style.cssText = `max-width: 0;overflow: visible;white-space: nowrap;`;
				cell.append(interp);
				row.append(cell);
				phTable.append(row);
			}
		}
		container.append(phTable);

		for (let { sh, symbols } of this.getSymbols()) {
			const stContainer = document.createElement('div');
			const stHeading = document.createElement('pre');
			stHeading.innerText = `Symbol table "${sh.getName(this)}" has ${symbols.length} entries:`;
			stContainer.append(stHeading);
			const stTable = document.createElement('table');
			const row = Symbol.GetHTMLNameRow();
			const num = document.createElement('td');
			num.innerText = 'Num';
			row.prepend(num);
			stTable.append(row);
			for (let symbol of symbols) {
				const row = symbol.toHTML(this);
				const num = document.createElement('td');
				num.innerText = symbols.indexOf(symbol).toString();
				row.prepend(num);
				stTable.append(row);
			}
			stContainer.append(stTable);
			container.append(stContainer);
		}

		for (let { sh, dynamic } of this.getDynamic()) {
			const dynContainer = document.createElement('div');
			const dynHeading = document.createElement('pre');
			dynHeading.innerText = `Dynamic section "${sh.getName(this)}" has ${dynamic.length} entries:`;
			dynContainer.append(dynHeading);
			const dynTable = document.createElement('table');
			const row = Dyn.GetHTMLNameRow();
			dynTable.append(row);
			for (let dyn of dynamic) {
				dynTable.append(dyn.toHTML(this));
			}
			dynContainer.append(dynTable);
			container.append(dynContainer);
		}

		for (let td of Array.from(container.getElementsByTagName('td'))) {
			td.style.paddingRight = '1em';
		}

		return container;
	}
}
