#pragma once
#include "symbol.hpp"
#include "pdb_server.hpp"
#include "../kernel/process.hpp"
#include "../util/file.hpp"
#include "../util/log.hpp"

#include <PDB.h>
#include <PDB_RawFile.h>
#include <PDB_DBIStream.h>
#include <PDB_GlobalSymbolStream.h>
#include <PDB_InfoStream.h>

#include <cstring>
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

		const auto pdb_path = find_pdb(*cv);
		if (pdb_path.empty())
			return;

		auto data = util::read_file(pdb_path);
		if (data.empty())
			return;

		if (!validate_pdb(data, cv))
		{
			LOG_ERR("invalid pdb: {}", pdb_path.string());
			return;
		}

		const auto raw = PDB::CreateRawFile(data.data());
		const auto dbi = PDB::CreateDBIStream(raw);

		if (dbi.HasValidSymbolRecordStream(raw) != PDB::ErrorCode::Success ||
			dbi.HasValidImageSectionStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto symbol_records = dbi.CreateSymbolRecordStream(raw);
		const auto sections = dbi.CreateImageSectionStream(raw);

		load_public_symbols(symbol_records, raw, dbi, sections, mod);
		load_global_symbols(symbol_records, raw, dbi, sections, mod);

		mod.symbols.sort();

		LOG_INFO("loaded {} symbols from {}", mod.symbols.size(), pdb_path.filename().string());
	}

private:
	std::vector<std::filesystem::path> search_paths_;

	static bool validate_pdb(const std::vector<std::uint8_t>& data, const pe::codeview_rsds* cv)
	{
		if (PDB::ValidateFile(data.data(), data.size()) != PDB::ErrorCode::Success)
			return false;

		if (PDB::HasValidDBIStream(PDB::CreateRawFile(data.data())) != PDB::ErrorCode::Success)
			return false;

		if (!cv)
			return true;

		const auto raw = PDB::CreateRawFile(data.data());
		const PDB::InfoStream info(raw);
		const auto* header = info.GetHeader();

		if (!header)
			return false;

		return std::memcmp(&header->guid, &cv->guid, sizeof(pe::guid)) == 0;
	}

	[[nodiscard]] std::filesystem::path find_pdb(const pe::codeview_rsds& cv) const
	{
		auto name = std::filesystem::path(cv.pdb_path()).filename();

		for (const auto& dir : search_paths_)
		{
			auto candidate = dir / name;
			if (std::filesystem::exists(candidate))
				return candidate;
		}

		if (std::filesystem::exists(name))
			return name;

		auto cached = pdb_server::cached_path(cv);
		if (std::filesystem::exists(cached))
			return cached;

		return pdb_server::download(cv);
	}

	static void load_public_symbols(
		const PDB::CoalescedMSFStream& symbol_records,
		const PDB::RawFile& raw, const PDB::DBIStream& dbi,
		const PDB::ImageSectionStream& sections, proc_module& mod)
	{
		if (dbi.HasValidPublicSymbolStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto pub = dbi.CreatePublicSymbolStream(raw);

		for (const auto& hash : pub.GetRecords())
		{
			const auto* record = pub.GetRecord(symbol_records, hash);

			if (!record || record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32)
				continue;

			const auto rva = sections.ConvertSectionOffsetToRVA(
				record->data.S_PUB32.section, record->data.S_PUB32.offset);

			if (rva == 0)
				continue;

			mod.symbols.insert(
				record->data.S_PUB32.name, mod.addr + rva);
		}
	}

	static void load_global_symbols(
		const PDB::CoalescedMSFStream& symbol_records,
		const PDB::RawFile& raw, const PDB::DBIStream& dbi,
		const PDB::ImageSectionStream& sections, proc_module& mod)
	{
		if (dbi.HasValidGlobalSymbolStream(raw) != PDB::ErrorCode::Success)
			return;

		const auto global = dbi.CreateGlobalSymbolStream(raw);

		for (const auto& hash : global.GetRecords())
		{
			const auto* record = global.GetRecord(symbol_records, hash);

			if (!record)
				continue;

			const auto kind = record->header.kind;

			if (kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32 ||
				kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32 ||
				kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID ||
				kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID)
			{
				const auto& proc = record->data.S_LPROC32;
				const auto rva = sections.ConvertSectionOffsetToRVA(proc.section, proc.offset);

				if (rva != 0)
					mod.symbols.insert(
						proc.name, mod.addr + rva, proc.codeSize);
			}
			else if (kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32 ||
					 kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
			{
				const auto& data = record->data.S_GDATA32;
				const auto rva = sections.ConvertSectionOffsetToRVA(data.section, data.offset);

				if (rva != 0)
					mod.symbols.insert(
						data.name, mod.addr + rva);
			}
		}
	}
};
