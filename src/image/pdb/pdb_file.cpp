#include "pdb_file.hpp"
#include "symbol_server.hpp"

#include <raw_pdb/PDB.h>
#include <raw_pdb/PDB_RawFile.h>
#include <raw_pdb/PDB_DBIStream.h>
#include <raw_pdb/PDB_PublicSymbolStream.h>
#include <raw_pdb/PDB_GlobalSymbolStream.h>
#include <raw_pdb/PDB_ImageSectionStream.h>

#include <fstream>
#include <format>
#include <stdexcept>

using symbol_kind = PDB::CodeView::DBI::SymbolRecordKind;

static void insert_symbol(
	std::vector<pdb::symbol_t>& symbols,
	std::unordered_map<std::string, std::size_t>& index,
	std::string name,
	const std::uint32_t rva,
	const std::uint16_t section,
	const std::uint32_t size = 0)
{
	if (index.contains(name))
	{
		return;
	}

	index[name] = symbols.size();
	symbols.push_back({ std::move(name), rva, size, section });
}

static void enumerate_public_symbols(
	std::vector<pdb::symbol_t>& symbols,
	std::unordered_map<std::string, std::size_t>& index,
	const PDB::RawFile& raw_file,
	const PDB::DBIStream& dbi_stream,
	const PDB::CoalescedMSFStream& symbol_records,
	const PDB::ImageSectionStream& sections)
{
	if (dbi_stream.HasValidPublicSymbolStream(raw_file) != PDB::ErrorCode::Success)
	{
		return;
	}

	const auto stream = dbi_stream.CreatePublicSymbolStream(raw_file);

	for (const auto& hash_record : stream.GetRecords())
	{
		const auto record = stream.GetRecord(symbol_records, hash_record);

		if (!record || record->header.kind != symbol_kind::S_PUB32)
		{
			continue;
		}

		const auto& pub = record->data.S_PUB32;
		const auto rva = sections.ConvertSectionOffsetToRVA(pub.section, pub.offset);

		if (rva != 0)
		{
			insert_symbol(symbols, index, pub.name, rva, pub.section);
		}
	}
}

static void enumerate_global_symbols(
	std::vector<pdb::symbol_t>& symbols,
	std::unordered_map<std::string, std::size_t>& index,
	const PDB::RawFile& raw_file,
	const PDB::DBIStream& dbi_stream,
	const PDB::CoalescedMSFStream& symbol_records,
	const PDB::ImageSectionStream& sections)
{
	if (dbi_stream.HasValidGlobalSymbolStream(raw_file) != PDB::ErrorCode::Success)
	{
		return;
	}

	const auto stream = dbi_stream.CreateGlobalSymbolStream(raw_file);

	for (const auto& hash_record : stream.GetRecords())
	{
		const auto record = stream.GetRecord(symbol_records, hash_record);

		if (!record)
		{
			continue;
		}

		const auto kind = record->header.kind;

		if (kind == symbol_kind::S_GPROC32 || kind == symbol_kind::S_LPROC32 ||
			kind == symbol_kind::S_GPROC32_ID || kind == symbol_kind::S_LPROC32_ID)
		{
			const auto& proc = record->data.S_LPROC32;
			const auto rva = sections.ConvertSectionOffsetToRVA(proc.section, proc.offset);

			if (rva != 0)
			{
				insert_symbol(symbols, index, proc.name, rva, proc.section, proc.codeSize);
			}
		}
		else if (kind == symbol_kind::S_GDATA32 || kind == symbol_kind::S_LDATA32)
		{
			const auto& data = record->data.S_GDATA32;
			const auto rva = sections.ConvertSectionOffsetToRVA(data.section, data.offset);

			if (rva != 0)
			{
				insert_symbol(symbols, index, data.name, rva, data.section);
			}
		}
	}
}

pdb::pdb_file_t::pdb_file_t(std::vector<std::uint8_t> data)
	:	data_(std::move(data))
{
	parse();
}

void pdb::pdb_file_t::parse()
{
	if (data_.empty())
	{
		throw std::runtime_error("PDB data is empty");
	}

	const auto error_code = PDB::ValidateFile(data_.data(), data_.size());

	if (error_code != PDB::ErrorCode::Success)
	{
		throw std::runtime_error(std::format("PDB validation failed (error {})", static_cast<std::uint32_t>(error_code)));
	}

	const auto raw_file = PDB::CreateRawFile(data_.data());

	if (PDB::HasValidDBIStream(raw_file) != PDB::ErrorCode::Success)
	{
		throw std::runtime_error("PDB has no valid DBI stream");
	}

	const auto dbi_stream = PDB::CreateDBIStream(raw_file);

	if (dbi_stream.HasValidSymbolRecordStream(raw_file) != PDB::ErrorCode::Success)
	{
		throw std::runtime_error("PDB has no valid symbol record stream");
	}

	if (dbi_stream.HasValidImageSectionStream(raw_file) != PDB::ErrorCode::Success)
	{
		throw std::runtime_error("PDB has no valid image section stream");
	}

	const auto symbol_records = dbi_stream.CreateSymbolRecordStream(raw_file);
	const auto sections = dbi_stream.CreateImageSectionStream(raw_file);

	enumerate_public_symbols(symbols_, name_to_index_, raw_file, dbi_stream, symbol_records, sections);
	enumerate_global_symbols(symbols_, name_to_index_, raw_file, dbi_stream, symbol_records, sections);
}

std::optional<pdb::symbol_t> pdb::pdb_file_t::find_symbol(const std::string_view name) const
{
	const auto it = name_to_index_.find(std::string(name));

	if (it == name_to_index_.end())
	{
		return std::nullopt;
	}

	return symbols_[it->second];
}

std::optional<std::uint32_t> pdb::pdb_file_t::find_rva(const std::string_view name) const
{
	const auto symbol = find_symbol(name);

	if (!symbol)
	{
		return std::nullopt;
	}

	return symbol->rva;
}

const std::vector<pdb::symbol_t>& pdb::pdb_file_t::symbols() const noexcept
{
	return symbols_;
}

std::size_t pdb::pdb_file_t::symbol_count() const noexcept
{
	return symbols_.size();
}

pdb::pdb_file_t pdb::load_pdb_from_file(const std::string_view path)
{
	std::ifstream file(std::string(path), std::ios::binary | std::ios::ate);

	if (!file.is_open())
	{
		throw std::runtime_error(std::format("failed to open PDB file '{}'", path));
	}

	const auto file_size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<std::uint8_t> data(static_cast<std::size_t>(file_size));
	file.read(reinterpret_cast<char*>(data.data()), file_size);

	return pdb_file_t(std::move(data));
}

pdb::pdb_file_t pdb::load_pdb_for_image(const std::string_view image_path)
{
	return pdb_file_t(download_pdb_for_image(image_path));
}

pdb::pdb_file_t pdb::load_pdb_for_image_buffer(const void* const image_base)
{
	const auto cv_info = extract_cv_info(image_base);

	if (!cv_info)
	{
		throw std::runtime_error("no CodeView debug info found");
	}

	const std::string_view pdb_path(cv_info->pdb_file_name);
	const auto last_sep = pdb_path.find_last_of("\\/");
	const auto name = last_sep != std::string_view::npos ? pdb_path.substr(last_sep + 1) : pdb_path;

	return pdb_file_t(download_pdb(name, *cv_info));
}
