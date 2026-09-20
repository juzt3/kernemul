#pragma once
#include "../../emu/object.hpp"
#include <cstddef>
#include <cstring>
#include <format>
#include <functional>
#include <string>

struct list_entry
{
	addr_t flink;
	addr_t blink;
};

template <typename T, std::size_t LinksOffset>
class win_linked_list
{
public:
	win_linked_list() noexcept = default;

	win_linked_list(addr_space& space_, const addr_t head_addr, std::string name = {},
		const bool monitored = false) noexcept
		:	head_(space_, head_addr, name.empty() ? std::string{} : name + ".Head", monitored),
			name_(std::move(name)), monitor_(monitored) { }

	void init()
	{
		const list_entry self{ head_.address(), head_.address() };
		head_.write(self);
	}

	void set_monitor(bool enabled) { monitor_ = enabled; }

	emu_object<T> push_back(const T& entry)
	{
		auto* const space_ = head_.space();

		// EPROCESS, ETHREAD and the loaded module entries are kernel structures: a driver
		// walking one of these lists on a real machine never lands on a user address.
		const auto entry_addr = space_->alloc(sizeof(T), prot_rw | prot_supervisor);
		return push_back(entry, entry_addr);
	}

	emu_object<T> push_back(emu_object<T>& obj)
	{
		return push_back(obj.read(), obj.address());
	}

	emu_object<T> push_back(const T& entry, const addr_t entry_addr)
	{
		auto* const space_ = head_.space();
		const auto head_addr = head_.address();
		auto head = head_.read();
		const auto tail_links = head.blink;

		T contents{};
		std::memcpy(&contents, &entry, sizeof(T));
		auto& links = links_of(contents);
		links.flink = head_addr;
		links.blink = tail_links;

		emu_object<T> obj(*space_, entry_addr,
			name_.empty() ? std::string{} : std::format("{}[0x{:X}]", name_, entry_addr));
		obj.write(contents);

		if (tail_links == head_addr)
			head.flink = links_addr(entry_addr);
		else
			write_flink(*space_, tail_links, links_addr(entry_addr));
		head.blink = links_addr(entry_addr);
		head_.write(head);

		if (monitor_)
			obj.monitor();

		return obj;
	}

	void remove(const addr_t entry_addr)
	{
		auto* const space_ = head_.space();
		const auto entry_links = read_links(*space_, links_addr(entry_addr));

		write_blink(*space_, entry_links.flink, entry_links.blink);
		write_flink(*space_, entry_links.blink, entry_links.flink);
	}

	void for_each(std::function<bool(emu_object<T>)> fn) const
	{
		auto* const space_ = head_.space();
		const auto head_addr = head_.address();
		auto cur = head_.read().flink;

		while (cur != head_addr)
		{
			const auto entry_addr = cur - LinksOffset;
			const auto links = read_links(*space_, cur);

			if (!fn(emu_object<T>(*space_, entry_addr)))
				break;

			cur = links.flink;
		}
	}

	[[nodiscard]] std::size_t size() const
	{
		std::size_t n = 0;
		for_each([&](auto) { ++n; return true; });
		return n;
	}

	[[nodiscard]] addr_t address() const noexcept { return head_.address(); }
	[[nodiscard]] bool empty() const { return head_.read().flink == head_.address(); }

private:
	static constexpr addr_t links_addr(const addr_t entry_addr)
	{
		return entry_addr + LinksOffset;
	}

	static list_entry& links_of(T& entry)
	{
		return *reinterpret_cast<list_entry*>(
			reinterpret_cast<char*>(&entry) + LinksOffset
		);
	}

	static list_entry read_links(addr_space& space_, const addr_t addr)
	{
		return space_.read_mem<list_entry>(addr);
	}

	static void write_flink(addr_space& space_, const addr_t at, const addr_t value)
	{
		space_.write_mem<addr_t>(at + offsetof(list_entry, flink), value);
	}

	static void write_blink(addr_space& space_, const addr_t at, const addr_t value)
	{
		space_.write_mem<addr_t>(at + offsetof(list_entry, blink), value);
	}

	emu_object<list_entry> head_;
	std::string name_;
	bool monitor_ = false;
};
