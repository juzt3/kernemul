#include "target.hpp"
#include "kernel/map.hpp"
#include "kernel/process.hpp"
#include "kernel/win/win_kernel.hpp"
#include "emu/calling_conv.hpp"
#include "util/log.hpp"
#include "util/string.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "emu/guest_emu.hpp"

#if defined(KERNEMUL_HAS_WHP)
	// Only the whp backend links Zydis; the instruction-level VM step tracer is whp-only anyway
	// (unicorn already single-steps cheaply enough, but the tracer is built around whp's
	// hook_code range stepping).
	#include <Zydis/Zydis.h>
#endif

#if defined(KERNEMUL_ARCH_ARM64)
	#include "kernel/win/arm64_win.hpp"
	#include "emu/arm64/mmu.hpp"
	#include "emu/arm64/calling_conv.hpp"

	namespace guest
	{
		using mmu          = arm64::mmu;
		using calling_conv = arm64_win_conv;
		using win_emulator = arm64_win_emulator;
	}
#else
	#include "kernel/win/x86_win.hpp"
	#include "emu/x86/mmu.hpp"
	#include "emu/x86/calling_conv.hpp"
	#include "emu/x86/arch.hpp"

	namespace guest
	{
		using mmu          = x86::mmu;
		using calling_conv = x86_win_conv;
		using win_emulator = x86_win_emulator;
	}
#endif

namespace
{

struct guest_image
{
	std::string name;
	bool driver = false;

	std::shared_ptr<thread> entry;
	std::shared_ptr<proc_module> module;
	addr_t driver_object = 0;
};

// Write the image as the guest sees it: every section at its rva, so the file is a direct picture
// of the mapped, relocated range. Section raw offsets and the alignments are rewritten to the va
// layout to match, which is what a live-memory dump looks like and lets a disassembler load the
// dump straight back with its own rva-based section table.
void dump_mapped_image(const proc_module& mod, addr_space& space,
	const std::filesystem::path& path)
{
	std::vector<std::uint8_t> out(mod.size);
	space.read_mem(mod.addr, out.data(), out.size());

	if (out.size() >= sizeof(pe::image))
	{
		// Casting the buffer is fine: the image has a DOS header, so the nt headers sit after it and
		// image::nt_hdrs() walks e_lfanew rather than assuming they are first.
		auto* const img = reinterpret_cast<pe::image*>(out.data());
		auto* const nt = img->nt_hdrs();

		if (nt && nt->ok())
		{
			auto* const opt = &nt->optional_hdr;
			const auto sect_align = opt->section_alignment;

			if (sect_align)
			{
				auto* const first = nt->first_section_hdr();
				const auto count = nt->num_sections();

				for (std::uint16_t i = 0; i < count; ++i)
				{
					auto* const s = &first[i];

					s->pointer_to_raw_data = s->virtual_address;
					s->size_of_raw_data = (s->virtual_size + sect_align - 1) & ~(sect_align - 1);
				}

				opt->file_alignment = sect_align;
				opt->size_of_headers =
					(opt->size_of_headers + sect_align - 1) & ~(sect_align - 1);
			}
		}
	}

	std::ofstream file(path, std::ios::binary);
	file.write(reinterpret_cast<const char*>(out.data()),
		static_cast<std::streamsize>(out.size()));

	LOG_INFO("dumped {} ({} bytes) to {}", mod.name, out.size(), path.string());
}

// Dump raw virtual-address ranges the image dump cannot cover: the driver object, a device object,
// any pool the driver allocated. Each range lands in its own file next to the image dump so a
// disassembler or a hex viewer can be pointed at exactly the bytes that were live.
void dump_regions(addr_space& space, const std::filesystem::path& base_path,
	const std::vector<std::pair<addr_t, std::size_t>>& regions)
{
	auto index = 0u;

	for (const auto& [va, size] : regions)
	{
		if (!size)
			continue;

		std::vector<std::uint8_t> buf(size);
		space.read_mem(va, buf.data(), buf.size());

		auto path = base_path;
		path += std::format(".{}.0x{:X}.bin", index++, va);

		std::ofstream file(path, std::ios::binary);
		file.write(reinterpret_cast<const char*>(buf.data()),
			static_cast<std::streamsize>(buf.size()));

		LOG_INFO("dumped region 0x{:X} ({} bytes) to {}", va, buf.size(), path.string());
	}
}

// Parse "0xVA:size,0xVA:size,..." into ranges. A size may be decimal or 0x-prefixed.
std::vector<std::pair<addr_t, std::size_t>> parse_regions(const char* spec)
{
	std::vector<std::pair<addr_t, std::size_t>> out;
	std::string_view s{spec};

	while (!s.empty())
	{
		const auto comma = s.find(',');
		const auto item = s.substr(0, comma);
		s = comma == std::string_view::npos ? std::string_view{} : s.substr(comma + 1);

		const auto colon = item.find(':');
		if (colon == std::string_view::npos)
			continue;

		const auto va = std::strtoull(std::string(item.substr(0, colon)).c_str(), nullptr, 0);
		const auto size = std::strtoull(std::string(item.substr(colon + 1)).c_str(), nullptr, 0);

		if (va && size)
			out.emplace_back(static_cast<addr_t>(va), static_cast<std::size_t>(size));
	}

	return out;
}

// Record the basic-block edges the guest actually takes inside its own image. Obfuscated code
// hides its real graph behind opaque predicates, but a block-edge trace only ever contains the
// edge that was taken, so the executed graph is recoverable from it. Written as a text log of
// "from -> to" so it can be read, diffed, and replayed into a disassembler.
struct block_trace
{
	std::mutex mtx;
	std::FILE* file = nullptr;
	std::unordered_set<std::uint64_t> edges;

	void record(const addr_t from, const addr_t to)
	{
		const auto key = (static_cast<std::uint64_t>(from) << 1) ^ static_cast<std::uint64_t>(to);

		std::lock_guard lock(mtx);

		if (!edges.insert(key).second)
			return;

		if (file)
			std::fprintf(file, "%llX -> %llX\n",
				static_cast<unsigned long long>(from), static_cast<unsigned long long>(to));
	}
};

// Register-level state at chosen guest addresses, for lifting the .be0 VM. The dispatcher is an
// indirect 'jmp rbp', so the value of the registers at that address is the only observable that
// reveals the VM's virtual instruction pointer, its decoded target, and its register file. Gated
// by KERNEMUL_REGS (comma-separated VAs); each address is logged once per distinct register state.
struct vm_state
{
	std::mutex mtx;
	std::FILE* file = nullptr;
	std::unordered_set<std::string> seen;

	void dump(vcpu& cpu, const addr_t va)
	{
		const auto regs = {
			std::pair{ "rax", x86::rax }, { "rcx", x86::rcx }, { "rdx", x86::rdx },
			{ "rbx", x86::rbx }, { "rsp", x86::rsp }, { "rbp", x86::rbp },
			{ "rsi", x86::rsi }, { "rdi", x86::rdi }, { "r8", x86::r8 },
			{ "r9", x86::r9 }, { "r10", x86::r10 }, { "r11", x86::r11 },
			{ "r12", x86::r12 }, { "r13", x86::r13 }, { "r14", x86::r14 },
			{ "r15", x86::r15 },
		};

		std::string line = std::format("va=0x{:X}", va);

		for (const auto& [name, r] : regs)
			line += std::format(" {}={:X}", name, cpu.reg(r));

		line += "\n";

		std::lock_guard lock(mtx);

		if (!seen.insert(line).second)
			return;

		if (file)
			std::fputs(line.c_str(), file);
	}
};

// Fetch-site recorder. At the bytecode fetch the interpreter computes the operand as
// [r10 + rdi - 1Ch] and decrypts it with r11, then dispatches on the result. Recording
// (address, keys, decrypted word, handler) is what lets the opcode->handler cipher be untangled.
struct fetch_trace
{
	std::mutex mtx;
	std::FILE* file = nullptr;      // raw, ordered (capped)
	std::FILE* hist_file = nullptr; // (at, dec, rbp) counts, written on flush
	std::unordered_map<std::string, std::uint64_t> counts;
	std::uint64_t total = 0;
	static constexpr std::uint64_t raw_cap = 500000;

	void record(vcpu& cpu, const addr_t va)
	{
		const auto rdi = cpu.reg(x86::rdi);
		const auto r10 = cpu.reg(x86::r10);
		const auto r11 = cpu.reg(x86::r11);
		const auto rbp = cpu.reg(x86::rbp);

		const auto ea = static_cast<addr_t>(rdi + r10 - 0x1C);

		std::uint32_t word = 0;

		try
		{
			word = cpu.read_virt_mem<std::uint32_t>(ea);
		}
		catch (...)
		{
			return;
		}

		const auto dec = word ^ static_cast<std::uint32_t>(r11);

		const auto line = std::format("at=0x{:X} rdi=0x{:X} r10=0x{:X} r11=0x{:X} "
			"word=0x{:X} dec=0x{:X} rbp=0x{:X}\n", va, rdi, r10, r11, word, dec, rbp);

		const auto key = std::format("at=0x{:X} dec=0x{:X} rbp=0x{:X}", va, dec, rbp);

		std::lock_guard lock(mtx);

		++counts[key];
		++total;

		if (file && total <= raw_cap)
			std::fputs(line.c_str(), file);
	}

	void flush()
	{
		std::lock_guard lock(mtx);

		if (!hist_file)
			return;

		std::fprintf(hist_file, "# total fetches: %llu, distinct: %zu\n",
			static_cast<unsigned long long>(total), counts.size());

		for (const auto& [k, c] : counts)
			std::fprintf(hist_file, "%llu %s\n", static_cast<unsigned long long>(c), k.c_str());
	}
};

#if defined(KERNEMUL_HAS_WHP)
// Instruction-level single-step over the VM's decode blocks. The threaded interpreter hides how the
// fetched, decrypted word becomes the next handler in `rbp`, because the code doing it is wrapped in
// junk. Stepping only the decode blocks (the block heads that edge into the convergence point) and
// logging each executed instruction with the full register file lets the mix be cancelled by
// construction offline: the register delta between consecutive steps is that instruction's effect,
// so the whole load -> decode -> `jmp rbp` chain is recoverable without guessing at the cipher.
struct vm_step
{
	std::mutex mtx;
	std::FILE* file = nullptr;
	std::vector<std::pair<addr_t, addr_t>> ranges; // [begin, end)

	addr_t window_base = 0;   // block head the current window belongs to
	std::uint64_t window_id = 0;
	addr_t last_base = 0;
	std::uint64_t seq = 0;

	[[nodiscard]] addr_t base_of(const addr_t pc) const
	{
		for (const auto& [b, e] : ranges)
			if (pc >= b && pc < e)
				return b;

		return 0;
	}

	void record(vcpu& cpu, const addr_t pc)
	{
		const auto base = base_of(pc);

		if (!base)
			return;

		std::uint64_t wid = 0;

		{
			std::lock_guard lock(mtx);

			if (base != last_base)
				++window_id;

			window_base = base;
			last_base = base;
			wid = window_id;
		}

		std::uint8_t bytes[16]{};
		std::size_t have = 0;

		try
		{
			cpu.read_virt_mem(pc, bytes, sizeof bytes);
			have = sizeof bytes;
		}
		catch (const std::exception&)
		{
			have = 0;
		}

		char text[192] = "?";
		std::size_t len = 0;

		if (have)
		{
			ZydisDecoder decoder;

			if (ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
				ZYDIS_STACK_WIDTH_64)))
			{
				ZydisDecodedInstruction insn;
				ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

				if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes, have, &insn, ops)))
				{
					ZydisFormatter formatter;

					if (ZYAN_SUCCESS(ZydisFormatterInit(&formatter,
						ZYDIS_FORMATTER_STYLE_INTEL)))
					{
						ZydisFormatterFormatInstruction(&formatter, &insn, ops,
							insn.operand_count_visible, text, sizeof text, pc, nullptr);
					}

					len = insn.length;
				}
			}
		}

		std::string hex;
		hex.reserve(len * 2);

		for (std::size_t i = 0; i < len; ++i)
			hex += std::format("{:02X}", bytes[i]);

		const auto get = [&](const reg_t reg) { return cpu.reg(reg); };

		const auto line = std::format(
			"w{} pc={:X} {:s} {} rax={:X} rbx={:X} rcx={:X} rdx={:X} rsi={:X} rdi={:X} "
			"rbp={:X} rsp={:X} r8={:X} r9={:X} r10={:X} r11={:X} r12={:X} r13={:X} r14={:X} "
			"r15={:X} rflags={:X}\n",
			wid, static_cast<std::uint64_t>(pc), hex, text,
			get(x86::rax), get(x86::rbx), get(x86::rcx), get(x86::rdx), get(x86::rsi),
			get(x86::rdi), get(x86::rbp), get(x86::rsp), get(x86::r8), get(x86::r9),
			get(x86::r10), get(x86::r11), get(x86::r12), get(x86::r13), get(x86::r14),
			get(x86::r15), get(x86::rflags));

		std::lock_guard lock(mtx);

		++seq;

		if (file)
		{
			std::fputs(line.c_str(), file);
			std::fflush(file);
		}
	}
};
#endif

void print_usage()
{
	LOG_INFO("usage: kernemul [image...]");
	LOG_INFO("examples:");
	LOG_INFO("  kernemul test_driver.sys");
	LOG_INFO("  kernemul test_printf.exe test_seh.exe");
	LOG_INFO("  kernemul test_driver.sys test_user.exe");
}

std::shared_ptr<thread> setup_driver(guest::win_emulator& win,
	const std::shared_ptr<guest::calling_conv>& conv, vcpu& cpu, const std::string& name,
	std::shared_ptr<proc_module>& out_module, addr_t& out_driver_object)
{
	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	const auto driver = krnl::map_img(proc, std::string(target::guest_fs_dir) + name, true);

	if (!driver)
	{
		LOG_ERR("failed to map {}", name);
		return {};
	}

	out_module = driver;

	// Up to the first dot, not the last: a variant build is named <service>.<variant>.sys, and
	// stem() would make vgk.calvin.sys a service called "vgk.calvin" that no driver expects.
	const auto file = std::filesystem::path(name).filename().string();
	const auto service = widen_string(file.substr(0, file.find('.')));

	const auto args = kernel.create_driver(*driver, service);

	out_driver_object = args.driver_object.address();

	const auto entry = win.create_kernel_thread(cpu, driver->entry_point);

	if (!entry)
	{
		LOG_ERR("failed to create a thread for {}", name);
		return {};
	}

	conv->set_arg(cpu, *entry, 0, args.driver_object.address());
	conv->set_arg(cpu, *entry, 1, args.registry_path.address());

	return entry;
}

bool setup_user_process(guest::win_emulator& win, vcpu& cpu, const std::string& name)
{
	const auto app = win.create_user_process(cpu, name);

	if (!app.thread)
	{
		LOG_ERR("failed to create a process for {}", name);
		return false;
	}

	return true;
}

}

int main(const int argc, const char* const* const argv)
{
	if (std::getenv("KERNEMUL_QUIET") != nullptr)
		spdlog::set_level(spdlog::level::warn);

	LOG_INFO("kernemul targeting {}", target::name);

	std::vector<std::string> names(argv + 1, argv + argc);

	if (names.empty())
	{
		print_usage();
		return 1;
	}

	std::vector<guest_image> images;
	images.reserve(names.size());

	for (auto& name : names)
	{
		if (!std::filesystem::exists(std::string(target::guest_fs_dir) + name))
		{
			LOG_ERR("{} is not in {}", name, target::guest_fs_dir);
			return 1;
		}

		const bool driver = name.ends_with(".sys");

		images.push_back({ std::move(name), driver, {} });
	}

	auto mem = std::make_shared<guest::mmu>();
	auto conv = std::make_shared<guest::calling_conv>();
	auto e = make_guest_emu(mem, conv);

	guest::win_emulator win(e);

	win.create_vcpus(vcpu_count);

	const auto cpu = win.cpus().front();

	set_log_cpu(cpu.get());

	for (auto& image : images)
	{
		if (image.driver)
		{
			image.entry = setup_driver(win, conv, *cpu, image.name, image.module,
				image.driver_object);

			if (!image.entry)
				return 1;
		}
		else if (!setup_user_process(win, *cpu, image.name))
		{
			return 1;
		}
	}

	// Fetch-site trace: records the bytecode word and decrypt keys at the interpreter's fetch.
	auto fetch = std::make_shared<fetch_trace>();

	// The image is only fully mapped and relocated once the guest has started, and a driver may
	// also write to its own sections as it runs, so the meaningful picture exists only after a
	// moment of execution. A watcher waits it out and reads the mapping out of the address space.
	std::thread dumper;

	if (const auto* dump_path = std::getenv("KERNEMUL_DUMP"))
	{
		auto& proc = *win.kernel().sys_proc;
		auto mod = images.front().module;
		const auto driver_object = images.front().driver_object;
		const auto extra = std::getenv("KERNEMUL_DUMP_REGIONS")
			? parse_regions(std::getenv("KERNEMUL_DUMP_REGIONS"))
			: std::vector<std::pair<addr_t, std::size_t>>{};

		if (mod)
		{
			std::size_t delay_ms = 2500;

			if (const auto* d = std::getenv("KERNEMUL_DUMP_DELAY_MS"))
			{
				if (const auto v = std::strtoul(d, nullptr, 10); v)
					delay_ms = v;
			}

			dumper = std::thread([mod, &proc, path = std::string(dump_path), delay_ms,
				driver_object, extra, fetch]
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

				dump_mapped_image(*mod, *proc.addr_space(), path);

				// The driver object is a fixed size and holds the dispatch table, so it is always
				// worth pulling out; the extra ranges cover device objects and the driver's pool.
				auto regions = extra;

				if (driver_object)
					regions.emplace_back(driver_object, sizeof(_DRIVER_OBJECT));

				dump_regions(*proc.addr_space(), path, regions);

				fetch->flush();

				// The guest is a driver that never idles, so there is nothing to wait for after the
				// dump; leaving is what ends the run.
				std::_Exit(0);
			});
		}
	}

	// Basic-block trace over the driver image. Module hooks fire on the guest's cpu, so the
	// per-cpu previous pc is thread_local; the mutex only guards the shared edge set and file.
	auto trace = std::make_shared<block_trace>();

	if (const auto* trace_path = std::getenv("KERNEMUL_TRACE"))
	{
		auto mod = images.front().module;

		if (mod)
		{
			trace->file = std::fopen(trace_path, "w");

			auto& e = win.emu();
			e.hook_basic_block(mod->addr, mod->addr + mod->size - 1,
				[trace](vcpu&, addr_t pc, std::size_t)
				{
					static thread_local addr_t prev = 0;

					if (prev && prev != pc)
						trace->record(prev, pc);

					prev = pc;
				});
		}
	}

	// Per-address register dump for VM lifting. Points KERNEMUL_REGS at the dispatcher(s) so every
	// dispatch logs the register file, which is where the virtual instruction pointer lives.
	auto vmstate = std::make_shared<vm_state>();

	if (const auto* regs = std::getenv("KERNEMUL_REGS"))
	{
		vmstate->file = std::fopen(regs, "w");

		// KERNEMUL_REGS is the output file; KERNEMUL_REGS_AT is the comma-separated VA list.
		if (const auto* at = std::getenv("KERNEMUL_REGS_AT"))
		{
			std::string_view s{at};

			while (!s.empty())
			{
				const auto comma = s.find(',');
				const auto item = s.substr(0, comma);
				s = comma == std::string_view::npos ? std::string_view{} : s.substr(comma + 1);

				const auto va = std::strtoull(std::string(item).c_str(), nullptr, 0);

				if (!va)
					continue;

				win.emu().hook_code(va, va, [vmstate, va](vcpu& c, addr_t, std::size_t)
				{
					vmstate->dump(c, va);
				});
			}
		}
	}

	if (const auto* fetch_path = std::getenv("KERNEMUL_FETCH"))
	{
		fetch->file = std::fopen(fetch_path, "w");

		if (const auto* hist = std::getenv("KERNEMUL_FETCH_HIST"))
			fetch->hist_file = std::fopen(hist, "w");

		if (const auto* at = std::getenv("KERNEMUL_FETCH_AT"))
		{
			std::string_view s{at};

			while (!s.empty())
			{
				const auto comma = s.find(',');
				const auto item = s.substr(0, comma);
				s = comma == std::string_view::npos ? std::string_view{} : s.substr(comma + 1);

				const auto va = std::strtoull(std::string(item).c_str(), nullptr, 0);

				if (!va)
					continue;

				win.emu().hook_code(va, va, [fetch, va](vcpu& c, addr_t, std::size_t)
				{
					fetch->record(c, va);
				});
			}
		}
	}

#if defined(KERNEMUL_HAS_WHP)
	// Instruction-level trace of the VM's decode blocks: KERNEMUL_VMSTEP is the output file,
	// KERNEMUL_VMSTEP_AT the comma-separated block heads to single-step, KERNEMUL_VMSTEP_LEN the
	// bytes to cover from each (default 0x400).
	auto vmstep = std::make_shared<vm_step>();

	if (const auto* path = std::getenv("KERNEMUL_VMSTEP"))
	{
		vmstep->file = std::fopen(path, "w");

		std::size_t span = 0x400;

		if (const auto* l = std::getenv("KERNEMUL_VMSTEP_LEN"))
		{
			if (const auto v = std::strtoull(l, nullptr, 0); v)
				span = static_cast<std::size_t>(v);
		}

		if (const auto* at = std::getenv("KERNEMUL_VMSTEP_AT"))
		{
			std::string_view s{at};

			while (!s.empty())
			{
				const auto comma = s.find(',');
				const auto item = s.substr(0, comma);
				s = comma == std::string_view::npos ? std::string_view{} : s.substr(comma + 1);

				const auto va = std::strtoull(std::string(item).c_str(), nullptr, 0);

				if (!va)
					continue;

				vmstep->ranges.emplace_back(static_cast<addr_t>(va),
					static_cast<addr_t>(va + span));
			}
		}

		for (const auto& [begin, end] : vmstep->ranges)
		{
			win.emu().hook_code(begin, end - 1, [vmstep](vcpu& c, addr_t pc, std::size_t)
			{
				vmstep->record(c, pc);
			});
		}
	}
#endif

	// Kernel-export call observer: every redirected API call records the guest caller and the VM's
	// current handler pointer (rbp at the call site), which is what ties a handler to the API it
	// invokes. KERNEMUL_CALLS is the output file.
	if (const auto* calls = std::getenv("KERNEMUL_CALLS"))
	{
		if (auto* calls_file = std::fopen(calls, "w"))
		{
			win.kernel().on_redirect =
				[calls_file](vcpu& c, const std::string& mod, const std::string& name, addr_t addr)
			{
				addr_t caller = 0;

				try
				{
					caller = c.read_virt_mem<addr_t>(c.sp());
				}
				catch (const std::exception&)
				{
				}

				const auto handler = c.reg(x86::rbp);
				const auto tid = c.thread() ? static_cast<unsigned long long>(c.thread()->id()) : 0ull;
				const auto pc = static_cast<unsigned long long>(c.pc());

				const auto line = std::format("call {}!{} addr={:X} caller={:X} rbp={:X} tid={} pc={:X}\n",
					mod, name, static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(caller),
					static_cast<unsigned long long>(handler), tid, pc);

				std::fputs(line.c_str(), calls_file);
				std::fflush(calls_file);
			};
		}
	}

	// IOCTL probe: once the driver has created its device, dispatch synthetic IRP_MJ_DEVICE_CONTROL
	// requests directly (bypassing the open/CREATE path) and record what each control code returns.
	// KERNEMUL_IOCTL is the output file. It runs on the emulator thread from a one-shot code hook,
	// the same nesting the redirected syscalls use.
	if (const auto* ioctl_path = std::getenv("KERNEMUL_IOCTL"))
	{
		if (auto* ioctl_file = std::fopen(ioctl_path, "w"))
		{
			auto fired = std::make_shared<std::atomic<bool>>(false);
			const auto probe_pc = static_cast<addr_t>(0xFFFFF80001DE778A);

			win.emu().hook_code(probe_pc, probe_pc,
				[&win, ioctl_file, fired](vcpu& c, addr_t, std::size_t)
			{
				if (fired->load(std::memory_order_relaxed))
					return;

				const auto device = win.kernel().find_device("\\Device\\BattlEye");

				if (!device)
					return;

				// The device exists from early in DriverEntry, but the dispatch table is filled in
				// after it; wait until the device-control slot is set or every request is a no-op.
				const auto driver_object =
					c.read_virt_mem<addr_t>(device + offsetof(_DEVICE_OBJECT, DriverObject));
				const auto control_routine = c.read_virt_mem<addr_t>(driver_object
					+ offsetof(_DRIVER_OBJECT, MajorFunction) + irp_mj_device_control * sizeof(addr_t));

				if (!control_routine)
					return;

				if (fired->exchange(true))
					return;

				auto& space = *c.curr_addr_space();
				const auto in = space.alloc(0x1000, prot_rw | prot_supervisor);
				const auto out = space.alloc(0x1000, prot_rw | prot_supervisor);

				// A control handler may refuse a request whose stack location has no file object,
				// because a real one only arrives after a completed open. Hand it a synthetic one.
				const auto fake_file = space.alloc(sizeof(_FILE_OBJECT), prot_rw | prot_supervisor);
				_FILE_OBJECT file_body{};
				file_body.Type = io_type_file;
				file_body.Size = static_cast<short>(sizeof(_FILE_OBJECT));
				file_body.DeviceObject =
					reinterpret_cast<_DEVICE_OBJECT*>(static_cast<std::uintptr_t>(device));
				space.write_mem(fake_file, &file_body, sizeof file_body);

				std::uint32_t count = 1;

				if (const auto* n = std::getenv("KERNEMUL_IOCTL_N"))
				{
					if (const auto v = std::strtoul(n, nullptr, 0); v)
						count = static_cast<std::uint32_t>(v);
				}

				const auto create_routine = c.read_virt_mem<addr_t>(driver_object
					+ offsetof(_DRIVER_OBJECT, MajorFunction) + irp_mj_create * sizeof(addr_t));

				std::fprintf(ioctl_file, "# device=0x%llX file=0x%llX control=0x%llX create=0x%llX\n",
					static_cast<unsigned long long>(device),
					static_cast<unsigned long long>(fake_file),
					static_cast<unsigned long long>(control_routine),
					static_cast<unsigned long long>(create_routine));
				{
					const auto sd = c.read_virt_mem<addr_t>(device
						+ offsetof(_DEVICE_OBJECT, SecurityDescriptor));
					const auto dtype = c.read_virt_mem<std::uint32_t>(device
						+ offsetof(_DEVICE_OBJECT, DeviceType));
					const auto ch = c.read_virt_mem<std::uint32_t>(device
						+ offsetof(_DEVICE_OBJECT, Characteristics));

					std::fprintf(ioctl_file,
						"# device_object: SecurityDescriptor=0x%llX DeviceType=0x%X Characteristics=0x%X\n",
						static_cast<unsigned long long>(sd), dtype, ch);
				}

				for (const auto* probe_name : { "\\??\\BattlEye", "\\DosDevices\\BattlEye",
					"\\Device\\BattlEye", "\\\\.\\BattlEye" })
				{
					std::fprintf(ioctl_file, "find('%s')=0x%llX\n", probe_name,
						static_cast<unsigned long long>(win.kernel().find_device(probe_name)));
				}

				for (std::uint32_t mj = 0; mj <= 0x1B; ++mj)
				{
					const auto r = c.read_virt_mem<addr_t>(driver_object
						+ offsetof(_DRIVER_OBJECT, MajorFunction) + mj * sizeof(addr_t));

					if (r)
						std::fprintf(ioctl_file, "M[0x%02X]=0x%llX\n", mj,
							static_cast<unsigned long long>(r));
				}
				std::fflush(ioctl_file);

				// Reproduce the open's create dispatch in isolation so the fault can be traced.
				try
				{
					// Which fields of the file object the create routine reads tells what state a
					// later request is gated on, since a real open only differs by what it fills.
					std::FILE* fo_file = nullptr;

					if (const auto* fo_path = std::getenv("KERNEMUL_FILEOBJ"))
						fo_file = std::fopen(fo_path, "w");

					if (fo_file)
					{
						win.emu().hook_mem(fake_file, fake_file + sizeof(_FILE_OBJECT) - 1,
							static_cast<mem_prot>(prot_read | prot_write),
							[fo_file, fake_file](vcpu& fc, addr_t a, std::size_t, mem_prot p)
						{
							std::uint64_t v = 0;

							try
							{
								v = fc.read_virt_mem<std::uint64_t>(a);
							}
							catch (const std::exception&)
							{
							}

							std::fprintf(fo_file, "FO +0x%llX %s pc=0x%llX val=0x%llX\n",
								static_cast<unsigned long long>(a - fake_file),
								p == prot_read ? "R" : "W",
								static_cast<unsigned long long>(fc.pc()),
								static_cast<unsigned long long>(v));
							std::fflush(fo_file);
						});
					}

					const auto r = win.dispatch_irp(c, {
						.major = irp_mj_create,
						.device_object = device,
						.file_object = fake_file,
					});
					std::fprintf(ioctl_file, "create status=0x%08X info=%llu\n",
						static_cast<unsigned>(r.status),
						static_cast<unsigned long long>(r.information));

					if (fo_file)
						std::fclose(fo_file);
				}
				catch (const std::exception& e)
				{
					std::fprintf(ioctl_file, "create EXC %s\n", e.what());
				}
				catch (...)
				{
					std::fprintf(ioctl_file, "create EXC unknown\n");
				}

				{
					const auto fsc = c.read_virt_mem<addr_t>(fake_file
						+ offsetof(_FILE_OBJECT, FsContext));
					const auto fsc2 = c.read_virt_mem<addr_t>(fake_file
						+ offsetof(_FILE_OBJECT, FsContext2));

					std::fprintf(ioctl_file, "file object after create: FsContext=0x%llX FsContext2=0x%llX\n",
						static_cast<unsigned long long>(fsc),
						static_cast<unsigned long long>(fsc2));
				}
				std::fflush(ioctl_file);

				// Optional: watch the IoControlCode field of the synthetic IRP to find the VM
				// instruction that reads it. KERNEMUL_WATCH is the output file.
				if (const auto* watch_path = std::getenv("KERNEMUL_WATCH"))
				{
					if (auto* watch_file = std::fopen(watch_path, "w"))
					{
						auto wfired = std::make_shared<std::atomic<bool>>(false);

						win.emu().hook_code(control_routine, control_routine,
							[&win, watch_file, wfired](vcpu& cc, addr_t, std::size_t)
						{
							if (wfired->exchange(true))
								return;

							addr_t irp = 0, stack = 0;

							try
							{
								irp = cc.reg(x86::rdx);
								stack = cc.read_virt_mem<addr_t>(irp + 0xB8);
							}
							catch (const std::exception&)
							{
							}

							const auto code_addr = stack + 0x18;

							std::fprintf(watch_file,
								"# irp=0x%llX stackloc=0x%llX code_addr=0x%llX\n",
								static_cast<unsigned long long>(irp),
								static_cast<unsigned long long>(stack),
								static_cast<unsigned long long>(code_addr));
							std::fflush(watch_file);

							win.emu().hook_mem(code_addr, code_addr + 3, prot_read,
								[watch_file](vcpu& c2, addr_t a, std::size_t, mem_prot)
							{
								std::uint32_t v = 0;

								try
								{
									v = c2.read_virt_mem<std::uint32_t>(a);
								}
								catch (const std::exception&)
								{
								}

								std::fprintf(watch_file, "READ code@0x%llX pc=0x%llX val=0x%llX\n",
									static_cast<unsigned long long>(a),
									static_cast<unsigned long long>(c2.pc()),
									static_cast<unsigned long long>(v));
								std::fflush(watch_file);
							});
						});

						// The gate stores the control code into its interpreter stack at the
						// instruction below; watch that slot for the comparison that reads it.
						const auto store_pc = static_cast<addr_t>(0xFFFFF80001DC088B);
						auto slot_watch = std::make_shared<std::atomic<bool>>(false);

						win.emu().hook_code(store_pc, store_pc,
							[&win, watch_file, slot_watch](vcpu& c3, addr_t, std::size_t)
						{
							if (slot_watch->exchange(true))
								return;

							const auto slot = c3.reg(x86::rbx) + c3.reg(x86::r10) - 0x70319F99;
							std::fprintf(watch_file, "# slot=0x%llX\n",
								static_cast<unsigned long long>(slot));
							std::fflush(watch_file);

							win.emu().hook_mem(slot, slot + 3, prot_read,
								[watch_file](vcpu& c4, addr_t a, std::size_t, mem_prot)
							{
								std::uint32_t v = 0;

								try
								{
									v = c4.read_virt_mem<std::uint32_t>(a);
								}
								catch (const std::exception&)
								{
								}

								std::fprintf(watch_file, "READSLOT @0x%llX pc=0x%llX val=0x%llX\n",
									static_cast<unsigned long long>(a),
									static_cast<unsigned long long>(c4.pc()),
									static_cast<unsigned long long>(v));
								std::fflush(watch_file);
							});
						});
					}
				}

				// Fixed-address watch list (KERNEMUL_WATCH_ADDR, comma-separated) for memory the
				// gate touches at addresses that are stable across runs.
				if (const auto* addrs = std::getenv("KERNEMUL_WATCH_ADDR"))
				{
					const auto* watch_out = std::getenv("KERNEMUL_WATCH_ADDR_OUT");
					if (auto* wf = std::fopen(watch_out ? watch_out : "watch_addr.txt", "w"))
					{
						std::string_view s{addrs};

						while (!s.empty())
						{
							const auto comma = s.find(',');
							const auto item = s.substr(0, comma);
							s = comma == std::string_view::npos
								? std::string_view{} : s.substr(comma + 1);
							const auto va = std::strtoull(std::string(item).c_str(), nullptr, 0);

							if (!va)
								continue;

							win.emu().hook_mem(static_cast<addr_t>(va),
								static_cast<addr_t>(va) + 3, prot_rw,
								[wf](vcpu& c4, addr_t a, std::size_t, mem_prot p)
							{
								std::uint32_t v = 0;

								try { v = c4.read_virt_mem<std::uint32_t>(a); }
								catch (const std::exception&) {}

								std::fprintf(wf, "ACC @0x%llX pc=0x%llX val=0x%llX rw=%d\n",
									static_cast<unsigned long long>(a),
									static_cast<unsigned long long>(c4.pc()),
									static_cast<unsigned long long>(v),
									static_cast<int>(p));
								std::fflush(wf);
							});
						}
					}
				}

				std::uint32_t fixed_code = 0;

				if (const auto* cc = std::getenv("KERNEMUL_IOCTL_CODE"))
				{
					if (const auto v = std::strtoul(cc, nullptr, 0); v)
					{
						fixed_code = static_cast<std::uint32_t>(v);
						count = 1;
					}
				}

				for (std::uint32_t f = 0; f < count; ++f)
				{
					const std::uint32_t code = fixed_code ? fixed_code : ((0x22u << 16) | (f << 2));

					try
					{
						const auto r = win.dispatch_irp(c, {
							.major = irp_mj_device_control,
							.device_object = device,
							.file_object = fake_file,
							.control_code = code,
							.input_buffer = in,
							.input_length = 0x20,
							.output_buffer = out,
							.output_length = 0x20,
						});

						std::fprintf(ioctl_file, "code=0x%08X status=0x%08X info=%llu\n", code,
							static_cast<unsigned>(r.status),
							static_cast<unsigned long long>(r.information));
					}
					catch (const std::exception& e)
					{
						std::fprintf(ioctl_file, "code=0x%08X EXC %s\n", code, e.what());
					}
					catch (...)
					{
						std::fprintf(ioctl_file, "code=0x%08X EXC unknown\n", code);
					}

					std::fflush(ioctl_file);
				}

				std::fclose(ioctl_file);
				std::_Exit(0);
			});
		}
	}

#if defined(KERNEMUL_HAS_WHP)
	// Contiguous VM linearization: sweep `.be0` with Zydis, find every instruction whose destination
	// is `rbp`, and hook only those. Every VM step ends at one of them, so the writes form a
	// contiguous transition stream with far less cost than single-stepping all of `.be0`.
	if (const auto* rbpw_path = std::getenv("KERNEMUL_RBPW"))
	{
		if (auto* rbpw_file = std::fopen(rbpw_path, "w"))
		{
			auto& space = *win.kernel().sys_proc->addr_space();
			const addr_t be0_lo = 0xFFFFF800019F7000;
			const addr_t be0_hi = 0xFFFFF8000215E000;

			std::fprintf(rbpw_file, "# rbp-write filter over .be0\n");
			std::fflush(rbpw_file);

			// The callback fires for every instruction in `.be0`; it decodes the instruction and
			// logs only the ones whose destination is `rbp`, so the output stays small.
			win.emu().hook_code(be0_lo, be0_hi - 1,
				[rbpw_file](vcpu& c, addr_t pc, std::size_t)
			{
				std::uint8_t bytes[16]{};
				ZydisDecodedInstruction in2;
				ZydisDecodedOperand op2[ZYDIS_MAX_OPERAND_COUNT];

				try
				{
					c.read_virt_mem(pc, bytes, sizeof bytes);
				}
				catch (const std::exception&)
				{
					return;
				}

				ZydisDecoder d2;
				ZydisDecoderInit(&d2, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

				if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&d2, bytes, sizeof bytes, &in2, op2)))
					return;

				if (in2.operand_count_visible < 1 || op2[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
					return;

				// Full 64-bit rbp only: the VM's epilogues move the handler pointer wholesale.
				// Partial-width writes (bpl/bp/ebp) are junk arithmetic, not dispatch.
				if (op2[0].reg.value != ZYDIS_REGISTER_RBP)
					return;

				// Only the arithmetic forms the VM uses for its epilogues; this drops function
				// prologue/epilogue noise (`push rbp` / `mov rbp,rsp` / `pop rbp`).
				switch (in2.mnemonic)
				{
				case ZYDIS_MNEMONIC_ADC:
				case ZYDIS_MNEMONIC_ADD:
					break;
				default:
					return;
				}

				char text[128] = "?";
				ZydisFormatter fm;
				ZydisFormatterInit(&fm, ZYDIS_FORMATTER_STYLE_INTEL);
				ZydisFormatterFormatInstruction(&fm, &in2, op2, in2.operand_count_visible, text,
					sizeof text, pc, nullptr);

				std::fprintf(rbpw_file,
					"RBW pc=%llX %s rbp=%llX rdi=%llX r11=%llX r10=%llX\n",
					static_cast<unsigned long long>(pc), text,
					static_cast<unsigned long long>(c.reg(x86::rbp)),
					static_cast<unsigned long long>(c.reg(x86::rdi)),
					static_cast<unsigned long long>(c.reg(x86::r11)),
					static_cast<unsigned long long>(c.reg(x86::r10)));
				std::fflush(rbpw_file);
			});
		}
	}
#endif

	win.run_all();
	if (dumper.joinable())
		dumper.join();
	for (const auto& image : images)
	{
		if (image.entry)
			LOG_INFO("{} returned, status=0x{:X}", image.name, conv->read_ret(*cpu, *image.entry));
		else
			LOG_INFO("{} finished", image.name);
	}

	return 0;
}
