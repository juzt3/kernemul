#pragma once
#include "../../emu/object.hpp"
#include "string.hpp"
#include "process_params.hpp"

class ldr_module_list
{
public:
	ldr_module_list() = default;

	ldr_module_list(win_user_mem& mem, addr_t ldr_addr)
		:	ldr_(mem.space(), ldr_addr)
	{
		_PEB_LDR_DATA data{};
		data.Length = sizeof(_PEB_LDR_DATA);
		data.Initialized = 1;

		const auto head_load = ldr_addr + offsetof(_PEB_LDR_DATA, InLoadOrderModuleList);
		const auto head_mem  = ldr_addr + offsetof(_PEB_LDR_DATA, InMemoryOrderModuleList);
		const auto head_init = ldr_addr + offsetof(_PEB_LDR_DATA, InInitializationOrderModuleList);

		data.InLoadOrderModuleList = guest_links(head_load, head_load);
		data.InMemoryOrderModuleList = guest_links(head_mem, head_mem);
		data.InInitializationOrderModuleList = guest_links(head_init, head_init);

		ldr_.write(data);
	}

	// LDR_DATA_TABLE_ENTRY::Flags. An exe is not a loaded-and-initialised dll.
	static constexpr std::uint32_t dll_flags = 0x001C4004;
	static constexpr std::uint32_t image_flags = 0x00004000;

	void add_module(win_user_mem& mem, addr_t base, addr_t entry_point,
		std::uint32_t size, const std::string& name, bool in_init_order,
		std::uint32_t flags = dll_flags)
	{
		const auto entry_addr = mem.alloc(sizeof(_LDR_DATA_TABLE_ENTRY), prot_rw);

		const auto wide_name = widen_string(name);
		const auto full_path = std::u16string(system32_dir) + wide_name;

		_LDR_DATA_TABLE_ENTRY entry{};
		entry.DllBase = guest_ptr(base);
		entry.EntryPoint = guest_ptr(entry_point);
		entry.SizeOfImage = size;
		entry.Flags = flags;
		entry.ObsoleteLoadCount = 0xFFFF;

		entry.FullDllName = win::init_unicode_string(mem, full_path);
		entry.BaseDllName = win::init_unicode_string(mem, wide_name);

		const auto hash_links = entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY, HashLinks);
		entry.HashLinks = guest_links(hash_links, hash_links);

		const auto ldr_addr = ldr_.address();

		insert_tail(mem.space(), entry.InLoadOrderLinks,
			ldr_addr + offsetof(_PEB_LDR_DATA, InLoadOrderModuleList),
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));

		insert_tail(mem.space(), entry.InMemoryOrderLinks,
			ldr_addr + offsetof(_PEB_LDR_DATA, InMemoryOrderModuleList),
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		if (in_init_order)
		{
			insert_tail(mem.space(), entry.InInitializationOrderLinks,
				ldr_addr + offsetof(_PEB_LDR_DATA, InInitializationOrderModuleList),
				entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks));
		}

		mem.write_mem(entry_addr, &entry, sizeof(entry));
	}

	addr_t address() const { return ldr_.address(); }

private:
	static void insert_tail(addr_space& space, _LIST_ENTRY& entry_links,
		addr_t head_addr, addr_t entry_links_addr)
	{
		const auto head = space.read_mem<_LIST_ENTRY>(head_addr);
		const auto old_tail = guest_va(head.Blink);

		entry_links = guest_links(head_addr, old_tail);

		if (old_tail == head_addr)
			space.write_mem<addr_t>(head_addr, entry_links_addr);
		else
			space.write_mem<addr_t>(old_tail, entry_links_addr);

		space.write_mem<addr_t>(head_addr + sizeof(addr_t), entry_links_addr);
	}

	emu_object<_PEB_LDR_DATA> ldr_;
};
