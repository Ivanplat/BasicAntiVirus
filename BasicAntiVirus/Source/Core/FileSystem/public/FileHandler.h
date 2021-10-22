#pragma once
#include "pch.h"
/// \file
///\brief


class FileHandler
{
public:
	/// <summary>
	/// Default constructor
	/// </summary>
	explicit FileHandler() noexcept = default;
	/// <summary>
	/// Default destructor
	/// </summary>
	virtual ~FileHandler() noexcept = default;
public:
	/// <summary>
	/// Structure that contains a info from/to binary file
	/// </summary>
	struct BinData
	{

	};
public:
	/// <summary>
	/// Methode to write new information to an existing binary file
	/// </summary>
	/// <returns>void</returns>
	virtual void WriteToBinFile(std::string FilePath, std::string NewData);
	/// <summary>
	/// Methode for reading an information from an existing binary file
	/// </summary>
	/// <returns>std::string</returns>
	virtual std::string ReadFromBinFile(std::string FilePath);
};