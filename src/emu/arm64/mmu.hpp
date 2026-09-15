#pragma once
#include "../mmu.hpp"
#include "addr_space.hpp"
#include <unordered_map>

namespace arm64
{
	class mmu : public ::mmu
	{
	public:
		std::size_t page_size() const override { return 0x1000; }

		void map_virt(::addr_space& space, addr_t va, std::size_t size, mem_prot prot) override;
		void map_virt_phys(::addr_space& space, addr_t va, addr_t pa, std::size_t size, mem_prot prot) override;
		void unmap_virt(::addr_space& space, addr_t va, std::size_t size) override;
		void read_virt(const ::addr_space& space, addr_t va, void* buf, std::size_t size) override;
		void write_virt(const ::addr_space& space, addr_t va, const void* buf, std::size_t size) override;
		void prot_virt(::addr_space& space, addr_t va, std::size_t size, mem_prot prot) override;

		std::optional<addr_t> virt_to_phys(const ::addr_space& space, addr_t va) override;
		std::optional<addr_t> phys_to_virt(const ::addr_space& space, addr_t pa) override;

		std::shared_ptr<::addr_space> create_addr_space() override;
		void destroy_addr_space(std::shared_ptr<::addr_space> space) override;
		std::shared_ptr<::addr_space> curr_addr_space(vcpu& cpu) override;
		void init_vcpu(vcpu& cpu) override;
		void switch_to(vcpu& cpu, std::shared_ptr<::addr_space> space) override;

	private:
		static constexpr std::size_t page_shift = 12;

		std::unordered_map<addr_t, std::shared_ptr<::addr_space>> spaces_;

		// The first address space level 0 table; every later space copies its upper half.
		addr_t kernel_ttbr_pa_ = 0;

		static addr_space& as_arm64(::addr_space& space);
		static const addr_space& as_arm64(const ::addr_space& space);

		static std::uint64_t page_attrs(mem_prot prot);

		std::optional<addr_t> translate_virt(const addr_space& space, addr_t page);

		addr_t ensure_table(addr_t table_pa, std::size_t index);
		void map_page(addr_space& space, addr_t va, addr_t pa, mem_prot prot);
		void unmap_page(addr_space& space, addr_t va);

		addr_t walk_to_l3(const addr_space& space, addr_t va);

		void copy_virt(const addr_space& space, addr_t va, void* buf, std::size_t size, bool write);

		void flush_all_tlb();
	};
}
