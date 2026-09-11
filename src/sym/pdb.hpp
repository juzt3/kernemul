#pragma once
#include "symbol.hpp"
#include "../kernel/process.hpp"
#include "../util/file.hpp"
#include "../util/log.hpp"

#include <PDB.h>
#include <PDB_RawFile.h>
#include <PDB_DBIStream.h>
#include <PDB_InfoStream.h>

#include <filesystem>
#include <vector>

struct pdb_symbols : symbols
{
	explicit pdb_symbols(std::vector<std::filesystem::path> search_paths = {})
		: search_paths_(std::move(search_paths)) { }

	void load(proc_module& mod) override
	{
		const auto* img = mod.pe();
		if (!img)
			return;

		const auto* cv = img->codeview();
		if (!cv)
			return;

		const auto pdb_path = find_pdb(cv->pdb_path());
		if (pdb_path.empty())
		{
			LOG_WARN("pdb not found: {}", std::string(cv->pdb_path()));
			return;
		}

		auto data = util::read_file(pdb_path);
		if (data.empty())
			return;

		if (PDB::ValidateFile(data.data(), data.size()) != PDB::ErrorCode::Success)
		{
			LOG_ERR("invalid pdb: {}", pdb_path.string());
			return;
		}

		const auto raw = PDB::CreateRawFile(data.data());

		if (PDB::HasValidDBIStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto dbi = PDB::CreateDBIStream(raw);

		if (dbi.HasValidImageSectionStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto sections = dbi.CreateImageSectionStream(raw);

		load_module_functions(raw, dbi, sections, mod);
		load_public_functions(raw, dbi, sections, mod);

		symbols::sort(mod.symbols_);

		LOG_INFO("loaded {} symbols from {}", mod.symbols_.size(), pdb_path.filename().string());
	}

private:
	std::vector<std::filesystem::path> search_paths_;

	[[nodiscard]] std::filesystem::path find_pdb(std::string_view pdb_name) const
	{
		auto name = std::filesystem::path(pdb_name).filename();

		for (const auto& dir : search_paths_)
		{
			auto candidate = dir / name;
			if (std::filesystem::exists(candidate))
				return candidate;
		}

		if (std::filesystem::exists(name))
			return name;

		return {};
	}

	static void load_module_functions(
		const PDB::RawFile& raw, const PDB::DBIStream& dbi,
		const PDB::ImageSectionStream& sections, proc_module& mod)
	{
		if (dbi.HasValidSymbolRecordStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto module_info = dbi.CreateModuleInfoStream(raw);

		for (const auto& module : module_info.GetModules())
		{
			if (!module.HasSymbolStream())
				continue;

			const auto stream = module.CreateSymbolStream(raw);

			stream.ForEachSymbol([&](const PDB::CodeView::DBI::Record* record)
			{
				const char* name = nullptr;
				uint32_t rva = 0;
				uint32_t size = 0;

				if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32)
				{
					name = record->data.S_LPROC32.name;
					rva = sections.ConvertSectionOffsetToRVA(record->data.S_LPROC32.section, record->data.S_LPROC32.offset);
					size = record->data.S_LPROC32.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32)
				{
					name = record->data.S_GPROC32.name;
					rva = sections.ConvertSectionOffsetToRVA(record->data.S_GPROC32.section, record->data.S_GPROC32.offset);
					size = record->data.S_GPROC32.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID)
				{
					name = record->data.S_LPROC32_ID.name;
					rva = sections.ConvertSectionOffsetToRVA(record->data.S_LPROC32_ID.section, record->data.S_LPROC32_ID.offset);
					size = record->data.S_LPROC32_ID.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID)
				{
					name = record->data.S_GPROC32_ID.name;
					rva = sections.ConvertSectionOffsetToRVA(record->data.S_GPROC32_ID.section, record->data.S_GPROC32_ID.offset);
					size = record->data.S_GPROC32_ID.codeSize;
				}

				if (!name || rva == 0)
					return;

				mod.symbols_.push_back({ name, mod.addr + rva, size });
			});
		}
	}

	static void load_public_functions(
		const PDB::RawFile& raw, const PDB::DBIStream& dbi,
		const PDB::ImageSectionStream& sections, proc_module& mod)
	{
		if (dbi.HasValidPublicSymbolStream(raw) != PDB::ErrorCode::Success ||
			dbi.HasValidSymbolRecordStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto symbol_records = dbi.CreateSymbolRecordStream(raw);
		const auto pub = dbi.CreatePublicSymbolStream(raw);

		for (const auto& hash : pub.GetRecords())
		{
			const auto* record = pub.GetRecord(symbol_records, hash);

			if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32)
				continue;

			if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
				PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u)
				continue;

			const auto rva = sections.ConvertSectionOffsetToRVA(
				record->data.S_PUB32.section, record->data.S_PUB32.offset);

			if (rva == 0)
				continue;

			const auto abs = mod.addr + rva;
			const bool already_known = std::ranges::any_of(mod.symbols_,
				[abs](const symbol_info& s) { return s.addr == abs; });

			if (already_known)
				continue;

			mod.symbols_.push_back({ record->data.S_PUB32.name, abs, 0 });
		}
	}
};
