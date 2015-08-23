#include "stdafx.h"
#include "BinaryUtils.h"

std::string AWS::Util::BinaryUtils::ToHex(const std::vector<unsigned char> &Digest)
{
	std::string sResult;
	sResult.reserve(Digest.size() * 2 + 1);
	for (auto it = Digest.cbegin(); it != Digest.cend(); ++it) {
		static const char dec2hex[16 + 1] = "0123456789abcdef";
		sResult += dec2hex[(*it >> 4) & 15];
		sResult += dec2hex[*it & 15];
	}
	return sResult;
}
