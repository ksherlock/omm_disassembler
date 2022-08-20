#include <sysexits.h>
#include <err.h>
#include <cxx/endian.h>
#include <cxx/mapped_file.h>
#include <cxx/vector.h>

#include "disassembler.h"

#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <unordered_map>

#include <unistd.h>


std::string tokens[] = {
#undef _
#undef __
#define __(x) #x
#define _(a,b,c) __(tk ## b) ,
#include "applesoft_tokens.h"
#undef _
#undef __
};



class omm_disassembler final : public disassembler {

public:
	omm_disassembler(std::vector<unsigned> &labels);

	~omm_disassembler() = default;

protected:

	virtual std::pair<std::string, std::string>
	format_data(unsigned size, const uint8_t *data);

	virtual std::pair<std::string, std::string>
	format_data(unsigned size, const std::string &data);

	virtual std::string ds() const;

	virtual int32_t next_label(int32_t pc);

	virtual std::string label_for_address(uint32_t address);
	virtual std::string label_for_zp(uint32_t address);


private:
	std::vector<unsigned> _labels;
	std::unordered_map<unsigned, std::string> _label_map;
	std::unordered_map<unsigned, std::string> _zp_label_map;
};

omm_disassembler::omm_disassembler(std::vector<unsigned> &labels)
	 : disassembler(disassembler::mpw | disassembler::msb_hexdump | disassembler::bit_hacks),
	 _labels(labels)
{

#undef _
#define _(a,b) { a, #b }

	_label_map.insert({

		// zp but called as jsr $00xx
		_(0xb1, chrget),
		_(0xb7, chrgot),

		 // usraddr
		_(0x03f8, ommvec),
		_(0x057b, ch80),

		_(0xbe6c, vpath1),
		_(0xbe6e, vpath2),

		_(0xc000, kbd),
		_(0xc010, strb),
		_(0xc019, rdvblbar),
		_(0xc036, cyareg),
		_(0xc061, cmdkey),


		_(0xd393, bltu),
		_(0xd3e3, reason),
		_(0xd412, error),
		_(0xd52c, inlin),
		_(0xd539, gdbufs),
		_(0xd553, inchr),
		_(0xd566, run),
		_(0xd61a, fndlin),
		_(0xd64b, scrtch),
		_(0xd66c, clearc),
		_(0xd683, stkini),
		_(0xd697, stxtpt),
		_(0xd7d2, newstt),
		_(0xd849, restor),
		_(0xd858, iscntc),
		_(0xd898, cont),
		_(0xd93e, goto),
		_(0xd995, data),
		_(0xd998, addon),
		_(0xd9a3, datan),
		_(0xd9a6, remn),
		_(0xda0c, linget),
		_(0xda46, let),
		_(0xda7b, getspt),
		_(0xdafb, crdo),
		_(0xdb3a, strout),
		_(0xdb3d, strprt),
		_(0xdb57, outspc),
		_(0xdb5a, outqst),
		_(0xdb5c, outdo),
		_(0xdd67, frmnum),
		_(0xdd6a, chknum),
		_(0xdd6c, chkstr),
		_(0xdd6d, chkval),
		_(0xdd7b, frmevl),
		_(0xde81, strtxt),
		_(0xdeb2, parchk),
		_(0xdeb8, chkcls),
		_(0xdebb, chkopn),
		_(0xdebe, chkcom),
		_(0xdec0, synchr),
		_(0xdfe3, ptrget),
		_(0xe07d, isletc),
		_(0xe10c, ayint),
		_(0xe2f2, givayf),
		_(0xe301, sngflt),
		_(0xe306, errdir),
		_(0xe3d5, strini),
		_(0xe3dd, strspa),
		_(0xe3e7, strlit),
		_(0xe3ed, strlt2),
		_(0xe42a, putnew),
		_(0xe452, getspa),
		_(0xe484, garbag),
		_(0xe5d4, movins),
		_(0xe5e2, movstr),
		_(0xe5fd, frestr),
		_(0xe6f8, getbyte),
		_(0xe752, getadr),
		_(0xed24, prdec),
		_(0xf941, prntax),
		_(0xfc10, bs),
		_(0xfc1a, up),
		_(0xfc66, lf),
		_(0xfd8e, crout),
		_(0xfdda, prbyte),
		_(0xfded, cout),

	});


	for (auto x : labels) {
		_label_map.emplace(x, to_x(x,4,'_'));
	}


	_zp_label_map = {

		_(0x00, d0),
		_(0x01, d1),
		_(0x02, d2),
		_(0x03, d3),
		_(0x04, strsav),
		_(0x0a, usrjmp),
		_(0x11, valtyp),
		_(0x19, number),
		_(0x1a, shapel),
		_(0x1c, hcolor1),
		_(0x20, wndlft),
		_(0x21, wndwid),
		_(0x22, wndtop),
		_(0x23, wndbot),
		_(0x24, ch),
		_(0x25, cv),
		_(0x28, basl), 
		_(0x32, invflg),
		_(0x33, prompt),
		_(0x36, cswl),
		_(0x38, kswl),
		_(0x3c, a1),
		_(0x3e, a2),
		_(0x42, a4),
		_(0x4e, rndl),
		_(0x50, linnum),
		_(0x52, temptr),
		_(0x5e, index),
		_(0x6d, strend),
		_(0x6f, fretop),
		_(0x71, frespc),
		_(0x73, himem),
		_(0x75, curlin),
		_(0x81, varnam),
		_(0x83, varpnt),
		_(0x85, forpnt),
		_(0x9b, lowtr),
		_(0x9d, fac),
		_(0xa0, strptr),
		_(0xa2, facsgn),
		_(0xb1, chrget),
		_(0xb7, chrgot),
		_(0xb8, txtptr),
		_(0xd8, errflg),
		_(0xda, errlin),
		_(0xde, errnum),
		//_(0xe4, hcolorz),
		_(0xf8, remstk),
		_(0xfa, varptr),
		_(0xfd, varptr2),
		_(0xe9, zfree1),
		_(0xef, zfree2),
		_(0xf0, zfree3),


		{ 0x3d, "a1+1" },
		{ 0x4f, "rndl+1" },
		{ 0xb9, "txtptr+1" },
		{ 0x51, "linum+1" },

		{ 0xe0, "prmtbl" },
		{ 0xe1, "prmtbl+1" },
		{ 0xe2, "prmtbl+2" },
		{ 0xe3, "prmtbl+3" },
		{ 0xe4, "prmtbl+4" },
		{ 0xe5, "prmtbl+5" },
	};

	recalc_next_label();
}

std::pair<std::string, std::string>
omm_disassembler::format_data(unsigned size, const uint8_t *data) {

	std::string tmp;

	for (unsigned i = 0; i < size; ++i) {
		if (i > 0) tmp += ", ";
		tmp += to_x(data[i], 2, '$');
	}

	return std::make_pair("dc.b", tmp);
}

std::pair<std::string, std::string>
omm_disassembler::format_data(unsigned size, const std::string &data) {
	switch(size) {
		case 1: return std::make_pair("dc.b", data);
		case 2: return std::make_pair("dc.w", data);
		case 3: return std::make_pair("dc.a", data);
		case 4: return std::make_pair("dc.l", data);

		default: { 
			std::string tmp;
			tmp = std::to_string(size) + " bytes";
			return std::make_pair(tmp, data);

		}
	}
}


std::string omm_disassembler::ds() const { return "ds.b"; }

int32_t omm_disassembler::next_label(int32_t pc) {
	if (_labels.empty()) return -1;
	if (pc == -1) return _labels.back();

	while (!_labels.empty()) {
		auto address = _labels.back();
		if (address > pc) return address;


		if (address == pc) {
			std::string tmp = label_for_address(pc);
			if (tmp.empty()) tmp = to_x(address,4,'_');
			emit(tmp);
		}
		else {
			warnx("Unable to place label _%04x",
				address);
		}
		_labels.pop_back();
	}

	if (_labels.empty()) return -1;
	return _labels.back();
}

std::string omm_disassembler::label_for_address(uint32_t address) {

	auto iter = _label_map.find(address);
	if (iter == _label_map.end()) return ""; // to_x(address, 4, '_');

	return iter->second;
}

std::string omm_disassembler::label_for_zp(uint32_t address) {

	auto iter = _zp_label_map.find(address);
	if (iter == _label_map.end()) return "";

	return iter->second;
}


#pragma pack(push, 1)

struct header {
	uint16_t version = 0;
	uint16_t id = 0;
	uint16_t size = 0;
	uint16_t org = 0;
	uint16_t amperct = 0;
	uint16_t kind = 0;
	uint16_t res1 = 0;
	uint16_t res2 = 0;
};

#pragma pack(pop)


template<class T>
void swap_if(T &t, std::false_type) {}

void swap_if(uint8_t &, std::true_type) {}

void swap_if(uint16_t &value, std::true_type) {
	value = __builtin_bswap16(value);
}

void swap_if(uint32_t &value, std::true_type) {
	value = __builtin_bswap32(value);
}

void swap_if(uint64_t &value, std::true_type) {
	value = __builtin_bswap64(value);
}


template<class T>
void le_to_host(T &value) {
	swap_if(value, std::integral_constant<bool, endian::native == endian::big>{});
}

template<class T>
uint8_t read_8(T &iter) {
	uint8_t tmp = *iter;
	++iter;
	return tmp;
}

template<class T>
uint16_t read_16(T &iter) {
	uint16_t tmp = 0;

	tmp |= *iter << 0;
	++iter;
	tmp |= *iter << 8;
	++iter;
	return tmp;
}

template<class T>
uint32_t read_32(T &iter) {
	uint32_t tmp = 0;

	tmp |= *iter << 0;
	++iter;
	tmp |= *iter << 8;
	++iter;
	tmp |= *iter << 16;
	++iter;
	tmp |= *iter << 24;
	++iter;


	return tmp;
}



// header, opcodes, immediate table, data
// opcodes end w/ 0 byte []


void disasm(const std::string &path) {
	std::error_code ec;


	mapped_file mf(path, ec);
	if (ec) {
		errx(1, "%s: %s", path.c_str(), ec.message().c_str());
	}

	if (mf.size() < 16 + 3) {
		errx(1, "%s: not an OMM file.", path.c_str());
	}

	header h;
	h = *(header *)mf.data();

	le_to_host(h.version);
	le_to_host(h.id);
	le_to_host(h.size);
	le_to_host(h.org);
	le_to_host(h.amperct);
	le_to_host(h.kind);
	le_to_host(h.res1);
	le_to_host(h.res2);


	// sanity check the header fields....

	if (h.res1 || h.res2 || h.kind) {
		errx(1, "%s: not an OMM file.", path.c_str());
	}

	if (h.version > 1 || h.size + 16 != mf.size()) {
		errx(1, "%s: not an OMM file.", path.c_str());
	}

	if (h.amperct && h.amperct >= h.size + h.org) {
		errx(1, "%s: not an OMM file.", path.c_str());
	}

	if (h.amperct && h.amperct <= h.org) {
		errx(1, "%s: not an OMM file.", path.c_str());
	}



	std::vector<unsigned> labels;
	std::pair<unsigned, unsigned> address_space = std::make_pair(h.org, h.org + h.size);
	std::pair<unsigned, unsigned> code_address_space;
	std::pair<unsigned, unsigned> data_address_space;
	std::pair<unsigned, unsigned> immediate_address_space;




	const auto begin = mf.begin() + 16;
	const auto end = mf.end();

	auto end_code = mf.end();
	auto end_immediate = mf.end();
	//auto end_data = mf.end();

	code_address_space.first = h.org;	

	analyzer anna;
	anna.set_m(false);
	anna.set_x(false);
	anna.set_pc(h.org);

	auto iter = begin;
	for ( ; iter != end; ++iter) {
		uint8_t op = *iter;
		if (op == 0 && anna.state()) {
			// version 1 requires 3 0s to terminate code.
			if (h.version == 0 || (anna.op() == 0 && anna.arg() == 0)) {
				end_code = iter;
				++iter;
				break;
			}
		}
		anna(op);
	}

	labels = anna.finish();
	erase_if(labels, [&address_space](uint32_t x){
		return x < address_space.first || x > address_space.second;
	});

	if (h.amperct) labels.push_back(h.amperct);

	unsigned offset = std::distance(begin, iter) + h.org;

	code_address_space.second = offset - 1;
	immediate_address_space.first = offset;

	// immediate table (keep references)
	for (; iter != end; offset += 2) {
		auto x = read_16(iter);
		if (x == 0) {
			end_immediate = iter - 2;
			break;
		}
		if (x >= address_space.first && x < address_space.second) labels.push_back(x);
		//labels.push_back(offset);
	}

	immediate_address_space.second = offset - 2;
	// data!

	data_address_space.first = offset;
	data_address_space.second = h.org + h.size;

	std::sort(labels.begin(), labels.end(), std::greater<unsigned>());
	labels.erase(std::unique(labels.begin(), labels.end()), labels.end());

	omm_disassembler d(labels);

	d.set_pc(h.org);
	d.set_m(false);
	d.set_x(false);

	d.emit("","longa", "off");
	d.emit("","longi", "off");
	d.emit("","case", "on");
	puts("");

	d.emit("","proc");


	puts("*------------------------------*");
	puts("*        Header Section        *");
	puts("*------------------------------*");
	puts("");

	d.emit("", "dc.w", d.to_x(h.version,4,'$'), "version");

	if (isprint(h.id & 0xff) && isprint(h.id >> 8)) {
		std::string tmp;
		tmp.push_back('\'');
		tmp.push_back(h.id & 0xff);
		tmp.push_back(h.id >> 8);
		tmp.push_back('\'');
		d.emit("","dc.w", tmp, "id");
	}
	else { 
		d.emit("", "dc.w", d.to_x(h.id,4,'$'), "id");
	}

	d.emit("", "dc.w", "end-start", "size " + d.to_x(h.size,4,'$'));
	d.emit("", "dc.w", d.to_x(h.org,4,'$'), "org");
	if (h.amperct) {
		d.emit("", "dc.w", d.to_x(h.amperct,4,'_'), "ampersand table");
	} else {
	d.emit("", "dc.w", d.to_x(h.amperct,4,'$'), "ampersand table");

	}
	d.emit("", "dc.w", d.to_x(h.kind,4,'$'), "kind");
	d.emit("", "dc.w", d.to_x(h.res1,4,'$'), "reserved");
	d.emit("", "dc.w", d.to_x(h.res2,4,'$'), "reserved");


	puts("");
	puts("*------------------------------*");
	puts("*         Code Section         *");
	puts("*------------------------------*");
	puts("");

	d.emit("start");

	for (iter = begin; iter != end_code; ++iter) {
		d(*iter);
	}

	d.set_code(false);
	// TODO -- v1 has 3 0 bytes.
	d(*iter++);
	d.flush();

	puts("");
	puts("*------------------------------*");
	puts("*       Immediate Section      *");
	puts("*------------------------------*");
	puts("");

	// word ptrs to data, terminated by word 0.



	for ( ; iter != end_immediate; ) {
		auto x = read_16(iter);
		std::string tmp;
		if (x < h.org) tmp = d.to_x(x, 4,'$');
		else tmp = d.to_x(x, 4, '_');
		d(tmp, 2, x);
	}
	d("0", 2);
	d.flush();
	iter += 2;


	puts("");
	puts("*------------------------------*");
	puts("*         Data Section         *");
	puts("*------------------------------*");
	puts("");

	// free-form data (may include code!)

	if (h.amperct) {
		auto xend = begin + (h.amperct - h.org);

		for (; iter != xend; ++iter) {
			d(*iter);
		}
		d.flush();

		// custom parser for the ampersand table.

		std::string tmp;
		unsigned pc = d.pc();
		puts("");
		d.emit("amperct");

		// usually token, 0 or 'text', 0
		// but could include: 
		// ON 'HANGUP' GOTO

		bool quoted = false;

		for (; iter != end; ++iter, ++pc) {
			uint8_t c= *iter;
			if (isascii(c) && isprint(c)) {
				if (!quoted) { tmp.push_back('\''); quoted = true; }
				tmp.push_back(c);
				continue;
			}

			if (!tmp.empty()) {
				if (quoted) {
					quoted = false;
					tmp.push_back('\'');
					tmp += ", ";
				}

				if (c == 0x00) {
					tmp += "0";
					d.emit("","dc.b", tmp);
					tmp.clear();
					continue;
				}
			}

			if (c >= 0x80 && c <= 0xea) {
				tmp += tokens[c - 0x80];
				tmp += ", ";
				continue;
			}

			d.emit("", "dc.b", d.to_x(c, 2, '$'));
			if (c == 0xff) {
				++pc;
				++iter;
				break;
			}
		}


		puts("");
		d.set_pc(pc);
	}


	for (; iter != end; ++iter) {
		d(*iter);
	}
	d.flush();
	puts("");
	d.emit("end");
	d.emit("","end");
	d.emit("","endp");

}


int main(int argc, char **argv) {

	int c;

	while ((c = getopt(argc, argv, "")) != -1) {

	}
	argc -=optind;
	argv += optind;

	for (int i = 0; i < argc; ++i) {
		disasm(argv[i]);
	}
	return 0;
}

