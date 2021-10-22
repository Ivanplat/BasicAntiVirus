#include "pch.h"
#include "Core/SHA-Checker/public/SHACheker.h"


std::string SHAChecker::GetHash(const std::string& buffer)
{
  auto hash1 = std::unique_ptr<Botan::HashFunction>(Botan::HashFunction::create("SHA-256"));
  if (hash1)
  {
	  hash1->update(buffer);
	  auto result = Botan::hex_encode(hash1->final());
#ifdef DEBUGMODE
	  std::wstring stemp = std::wstring(result.begin(), result.end());
	  LPCWSTR sw = (LPCWSTR)stemp.c_str();
	  MessageBox(NULL, sw, L"caption", NULL);
#endif
	  return result;
  }
  return "ERROR";
}
