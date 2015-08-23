#ifndef AWS_UTIL_BINARY_UTILS_H
#define AWS_UTIL_BINARY_UTILS_H

#include <vector>

#ifdef AWSUTIL_EXPORTS
#    define AWSUTIL_IMPEX __declspec(dllexport)
#    define AWSUTIL_TEMPLATE
#else
#    define AWSUTIL_IMPEX __declspec(dllimport)
#    define AWSUTIL_TEMPLATE extern
#endif

namespace AWS {
	namespace Util {
		class AWSUTIL_IMPEX BinaryUtils {
		public:
			static std::string ToHex(const std::vector<unsigned char> &Digest);
		};
	}
}

#endif // AWS_UTIL_BINARY_UTILS_H


