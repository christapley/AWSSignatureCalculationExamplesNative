#ifndef AWS_UTIL_URI_UTILS_H
#define AWS_UTIL_URI_UTILS_H

#include <string>

#ifdef AWSUTIL_EXPORTS
#    define AWSUTIL_IMPEX __declspec(dllexport)
#    define AWSUTIL_TEMPLATE
#else
#    define AWSUTIL_IMPEX __declspec(dllimport)
#    define AWSUTIL_TEMPLATE extern
#endif

namespace AWS {
	namespace Util {
		class AWSUTIL_IMPEX URIUtils {
		public:
			static std::string URLEncode(const std::string &URI);
			static std::string URLDecode(const std::string &URI);

			static std::string GetHostName(const std::string &URI);
		};
	}
}

#endif // AWS_UTIL_URI_UTILS_H


