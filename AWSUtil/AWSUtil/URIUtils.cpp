#include "URIUtils.h"

std::string AWS::Util::URIUtils::URLEncode(const std::string & URI)
{
	std::string sEncoded;
	sEncoded.reserve(URI.length());
	char Buffer[32];

	for (auto it = URI.cbegin(); it != URI.cend(); ++it) {
		if (isxdigit(*it) == 0) {
#ifdef WIN32
			sprintf_s(&Buffer[0], sizeof(Buffer), "%%%02x", static_cast<int>(*it));
#else
			_snprintf(&Buffer[0], sizeof(Buffer), "%%%02x", static_cast<int>(*it));
#endif
			sEncoded += Buffer;
		}
		else {
			sEncoded += *it;
		}
	}
	return sEncoded;
}

std::string AWS::Util::URIUtils::URLDecode(const std::string & URI)
{
	std::string sDecoded;
	char szTemp[] = "v";
	for (size_t nI = 0; nI < URI.length(); nI++) {
		if (URI[nI] == '%' && nI + 2 < URI.length() && isxdigit(URI[nI + 1]) != 0 && isxdigit(URI[nI + 2]) != 0) {
			sDecoded += static_cast<char>(strtol(URI.substr(++nI, 2).c_str(), NULL, 16));
			nI++;
		}
		else {
			sDecoded += URI[nI];
		}
	}
	return sDecoded;
}

std::string AWS::Util::URIUtils::GetHostName(const std::string & URI)
{
	size_t nStartPos = URI.find("//");
	if (nStartPos == std::string::npos) {
		// throw
		return "";
	}
	nStartPos += 2;
	size_t nEndPos = URI.find("/", nStartPos);
	return URI.substr(nStartPos, nEndPos == std::string::npos ? std::string::npos : nEndPos - nStartPos);
}
