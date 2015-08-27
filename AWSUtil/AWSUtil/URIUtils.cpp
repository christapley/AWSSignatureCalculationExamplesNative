#include "URIUtils.h"

std::string AWS::Util::URIUtils::URLEncode(const std::string & URI, bool bKeepSlashes)
{
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex << std::uppercase;

	if (bKeepSlashes) {
		for (auto it = URI.begin(); it != URI.end(); ++it) {
			std::string::value_type c = (*it);
			if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
				escaped << c;
				continue;
			}
			escaped << '%' << std::setw(2) << int((unsigned char)c);
		}
	}
	else {
		for (auto it = URI.begin(); it != URI.end(); ++it) {
			std::string::value_type c = (*it);
			if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
				escaped << c;
				continue;
			}
			escaped << '%' << std::setw(2) << int((unsigned char)c);
		}
	}
	return escaped.str();
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
