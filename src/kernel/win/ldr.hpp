#pragma once
#include "../../emu/object.hpp"
#include "string.hpp"
#include "process_params.hpp"

class ldr_module_list
{
public:
	ldr_module_list() = default;

	ldr_module_list(addr_space& space, addr_t ldr_addr)
		:	ldr_(space, ldr_addr)
	{
		_PEB_LDR_DATA64 data{};
		data.Length = sizeof(_PEB_LDR_DATA64);
		data.Initialized = 1;

		const auto head_load = ldr_addr + offsetof(_PEB_LDR_DATA64, InLoadOrderModuleList);
		const auto head_mem  = ldr_addr + offsetof(_PEB_LDR_DATA64, InMemoryOrderModuleList);
		const auto head_init = ldr_addr + offsetof(_PEB_LDR_DATA64, InInitializationOrderModuleList);

		data.InLoadOrderModuleList = { head_load, head_load };
		data.InMemoryOrderModuleList = { head_mem, head_mem };
		data.InInitializationOrderModuleList = { head_init, head_init };

		ldr_.write(data);
	}

	void add_module(addr_space& space, addr_t base, addr_t entry_point,
		std::uint32_t size, const std::string& name, bool in_init_order)
	{
		const auto entry_addr = space.alloc(ldr_data_table_entry64_alloc_size, prot_rw);

		const auto wide_name = widen_string(name);
		const auto full_path = std::wstring(system32_dir) + wide_name;

		_LDR_DATA_TABLE_ENTRY64 entry{};
		entry.DllBase = base;
		entry.EntryPoint = entry_point;
		entry.SizeOfImage = size;
		entry.Flags = 0x001C4004;
		entry.ObsoleteLoadCount = 0xFFFF;

		entry.FullDllName = win::init_unicode_string64(space, full_path);
		entry.BaseDllName = win::init_unicode_string64(space, wide_name);

		entry.HashLinks = {
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY64, HashLinks),
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY64, HashLinks)
		};

		const auto ldr_addr = ldr_.address();

		insert_tail(space, entry.InLoadOrderLinks,
			ldr_addr + offsetof(_PEB_LDR_DATA64, InLoadOrderModuleList),
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks));

		insert_tail(space, entry.InMemoryOrderLinks,
			ldr_addr + offsetof(_PEB_LDR_DATA64, InMemoryOrderModuleList),
			entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks));

		if (in_init_order)
		{
			insert_tail(space, entry.InInitializationOrderLinks,
				ldr_addr + offsetof(_PEB_LDR_DATA64, InInitializationOrderModuleList),
				entry_addr + offsetof(_LDR_DATA_TABLE_ENTRY64, InInitializationOrderLinks));
		}

		space.write_mem(entry_addr, &entry, sizeof(entry));
	}

	addr_t address() const { return ldr_.address(); }

private:
	static void insert_tail(addr_space& space, _LIST_ENTRY64& entry_links,
		addr_t head_addr, addr_t entry_links_addr)
	{
		const auto head = space.read_mem<_LIST_ENTRY64>(head_addr);
		const auto old_tail = head.Blink;

		entry_links.Flink = head_addr;
		entry_links.Blink = old_tail;

		if (old_tail == head_addr)
			space.write_mem<addr_t>(head_addr, entry_links_addr);
		else
			space.write_mem<addr_t>(old_tail, entry_links_addr);

		space.write_mem<addr_t>(head_addr + sizeof(addr_t), entry_links_addr);
	}

	emu_object<_PEB_LDR_DATA64> ldr_;
};
