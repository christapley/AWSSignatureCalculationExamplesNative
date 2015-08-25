
#include "Auth.h"
#include "URIUtils.h"
#include "BinaryUtils.h"

using namespace AWS;
using namespace Auth;


class AWS::Auth::AWS4SignerBase::Impl {
public:
	Impl(const std::string &sEndPointURL,
		const std::string &sHTTPMethod,
		const std::string &sServiceName,
		const std::string &sRegionName) :
		m_sEndPointURL(sEndPointURL),
		m_sHTTPMethod(sHTTPMethod),
		m_sServiceName(sServiceName),
		m_sRegionName(sRegionName) {}

	std::string m_sEndPointURL;
	std::string m_sHTTPMethod;
	std::string m_sServiceName;
	std::string m_sRegionName;

	static std::string EMPTY_BODY_SHA256;
	static std::string UNSIGNED_PAYLOAD;

	static std::string SCHEME;
	static std::string ALGORITHM;
	static std::string TERMINATOR;
private:
	Impl() {}
};

std::string AWS::Auth::AWS4SignerBase::Impl::EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
std::string AWS::Auth::AWS4SignerBase::Impl::UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

std::string AWS::Auth::AWS4SignerBase::Impl::SCHEME = "AWS4";
std::string AWS::Auth::AWS4SignerBase::Impl::ALGORITHM = "HMAC-SHA256";
std::string AWS::Auth::AWS4SignerBase::Impl::TERMINATOR = "aws4_request";

const std::string &AWS::Auth::AWS4SignerBase::EmptyBodySHA256()
{
	return AWS::Auth::AWS4SignerBase::Impl::EMPTY_BODY_SHA256;
}
const std::string &AWS::Auth::AWS4SignerBase::UnsignedPayload()
{
	return AWS::Auth::AWS4SignerBase::Impl::UNSIGNED_PAYLOAD;
}
const std::string &AWS::Auth::AWS4SignerBase::Scheme()
{
	return AWS::Auth::AWS4SignerBase::Impl::SCHEME;
}
const std::string &AWS::Auth::AWS4SignerBase::Algorithm()
{
	return AWS::Auth::AWS4SignerBase::Impl::ALGORITHM;
}
const std::string &AWS::Auth::AWS4SignerBase::Terminator()
{
	return AWS::Auth::AWS4SignerBase::Impl::TERMINATOR;
}


AWS::Auth::AWS4SignerBase::AWS4SignerBase(const std::string & sEndPointURL, const std::string & sHTTPMethod, const std::string & sServiceName, const std::string & sRegionName) : 
	m_pImpl(new Impl(sEndPointURL, sHTTPMethod, sServiceName, sRegionName))
{
}

AWS::Auth::AWS4SignerBase::~AWS4SignerBase()
{
}

const std::string &AWS::Auth::AWS4SignerBase::EndPointURL() const {
	return m_pImpl->m_sEndPointURL;
}

const std::string &AWS::Auth::AWS4SignerBase::HTTPMethod() const {
	return m_pImpl->m_sHTTPMethod;
}

const std::string &AWS::Auth::AWS4SignerBase::ServiceName() const {
	return m_pImpl->m_sServiceName;
}

const std::string &AWS::Auth::AWS4SignerBase::RegionName() const {
	return m_pImpl->m_sRegionName;
}

std::string AWS::Auth::AWS4SignerBase::GetCanonicalizedQueryString(const std::map<std::string, std::string>& Parameters)
{
	if (Parameters.empty()) {
		return std::string();
	}

	std::list<std::pair<std::string, std::string> > SortedParameters;
	for (auto it = Parameters.cbegin(); it != Parameters.cend(); ++it) {
		SortedParameters.push_back(std::pair<std::string, std::string>(it->first, it->second));
		std::string &HeaderName = SortedParameters.back().first;
		std::transform(HeaderName.begin(), HeaderName.end(), HeaderName.begin(), [](const char in) {
			if (in <= 'Z' && in >= 'A') return static_cast<int>(in - ('Z' - 'z'));
			return static_cast<int>(in);
		});
	}
	SortedParameters.sort([](const std::pair<std::string, std::string> &a, const std::pair<std::string, std::string> &b) {
		return a.first < b.first;
	});

	std::string sCanonicalParameters;
	for (auto it = SortedParameters.cbegin(); it != SortedParameters.cend(); ++it) {
		sCanonicalParameters.append(AWS::Util::URIUtils::URLEncode(it->first));
		sCanonicalParameters.append("=");
		sCanonicalParameters.append(AWS::Util::URIUtils::URLEncode(it->second));
		sCanonicalParameters.append("&");
	}
	if (!sCanonicalParameters.empty()) {
		sCanonicalParameters.pop_back();
	}
	return sCanonicalParameters;
}

std::string AWS::Auth::AWS4SignerBase::Hash(const std::string & sText)
{
	std::vector<unsigned char> Digest;
	Digest.resize(SHA256_DIGEST_SIZE);
	sha256(reinterpret_cast<const unsigned char *>(sText.c_str()), sText.length(), &Digest[0]);

	return AWS::Util::BinaryUtils::ToHex(Digest);
}

std::string AWS::Auth::AWS4SignerBase::Hash(const char * sData)
{
	std::vector<unsigned char> Digest;
	Digest.resize(SHA256_DIGEST_SIZE);
	sha256(reinterpret_cast<const unsigned char *>(sData), strlen(sData), &Digest[0]);

	return AWS::Util::BinaryUtils::ToHex(Digest);
}

std::string AWS::Auth::AWS4SignerBase::Hash(const std::vector<unsigned char> &Data)
{
	std::vector<unsigned char> Digest;
	Digest.resize(SHA256_DIGEST_SIZE);
	sha256(&Data[0], Data.size(), &Digest[0]);

	return AWS::Util::BinaryUtils::ToHex(Digest);
}

std::string AWS::Auth::AWS4SignerBase::GetCanonicalizedHeaderNames(const std::map<std::string, std::string>& Headers)
{
	std::list<std::string> HeaderNames;
	for (auto it = Headers.cbegin(); it != Headers.cend(); ++it) {
		HeaderNames.push_back(it->first);
		std::string &HeaderName = HeaderNames.back();
		std::transform(HeaderName.begin(), HeaderName.end(), HeaderName.begin(), [](const char in) {
			if (in <= 'Z' && in >= 'A') return static_cast<int>(in - ('Z' - 'z'));
			return static_cast<int>(in);
		});
	}
	HeaderNames.sort();
	
	std::string sCanonicalHeaderNames;
	for (auto it = HeaderNames.cbegin(); it != HeaderNames.cend(); ++it) {
		sCanonicalHeaderNames.append(*it);
		sCanonicalHeaderNames.append(";");
	}
	if (!sCanonicalHeaderNames.empty()) {
		sCanonicalHeaderNames.pop_back();
	}
	return sCanonicalHeaderNames;
}

std::string AWS::Auth::AWS4SignerBase::GetCanonicalizedHeaderString(const std::map<std::string, std::string>& Headers)
{
	if (Headers.empty()) {
		return std::string();
	}

	std::list<std::pair<std::string, std::string> > SortedHeaders;
	for (auto it = Headers.cbegin(); it != Headers.cend(); ++it) {
		SortedHeaders.push_back(std::pair<std::string, std::string>(it->first, it->second));
		std::string &HeaderName = SortedHeaders.back().first;
		std::transform(HeaderName.begin(), HeaderName.end(), HeaderName.begin(), [](const char in) {
			if (in <= 'Z' && in >= 'A') return static_cast<int>(in - ('Z' - 'z'));
			return static_cast<int>(in);
		});

		auto BothWhiteSpace = [](const char l, const char r) { return (l == r) && (l == ' '); };

		std::unique(HeaderName.begin(), HeaderName.end(), BothWhiteSpace);
		std::string &HeaderValue = SortedHeaders.back().second;
		std::unique(HeaderValue.begin(), HeaderValue.end(), BothWhiteSpace);
	}
	SortedHeaders.sort([](const std::pair<std::string, std::string> &a, const std::pair<std::string, std::string> &b) {
		return a.first < b.first;
	});
	
	std::string sCanonicalHeaderString;
	for (auto it = SortedHeaders.cbegin(); it != SortedHeaders.cend(); ++it) {
		sCanonicalHeaderString.append(it->first);
		sCanonicalHeaderString.append(":");
		sCanonicalHeaderString.append(it->second);
		sCanonicalHeaderString.append("\n");
	}
	return sCanonicalHeaderString;
}

std::string AWS::Auth::AWS4SignerBase::GetCanonicalRequest(const std::string & sEndPointURL, const std::string & sHTTPMethod, const std::string & sQueryParameters, const std::string & sCanonicalizedHeaderNames, const std::string & sCanonicalizedHeaders, const std::string & sBodyHash)
{
	std::string sCanonicalRequest =
		sHTTPMethod + "\n" +
		GetCanonicalizedResourcePath(sEndPointURL) + "\n" +
		sQueryParameters + "\n" +
		sCanonicalizedHeaders + "\n" +
		sCanonicalizedHeaderNames + "\n" +
		sBodyHash;
		return sCanonicalRequest;
}

std::string AWS::Auth::AWS4SignerBase::GetCanonicalizedResourcePath(const std::string & sEndPointURL)
{
	if (sEndPointURL.empty()) {
		return "/";
	}

	size_t nPos = sEndPointURL.find("//");
	if (nPos == std::string::npos) {
		return "/";
	}
	nPos = sEndPointURL.find("/", nPos+2);
	if (nPos == std::string::npos) {
		return "/";
	}
	return AWS::Util::URIUtils::URLEncode(sEndPointURL.substr(nPos, sEndPointURL.find("?", nPos + 1)));
}

std::string AWS::Auth::AWS4SignerBase::GetStringToSign(const std::string & sScheme, const std::string & sAlgorithm, const std::string & sDateTime, const std::string & sScope, const std::string & sCanonicalRequest)
{
	std::string sStringToSign =
		sScheme + "-" + sAlgorithm + "\n" +
		sDateTime + "\n" +
		sScope + "\n" +
		Hash(sCanonicalRequest); // must hash sCanonicalRequest
	return sStringToSign;
}

std::vector<unsigned char> AWS::Auth::AWS4SignerBase::Sign(const std::string & sStringData, const std::string &sKey)
{
	hmac_sha256_ctx Ctx;
	hmac_sha256_init(&Ctx, reinterpret_cast<const unsigned char *>(sKey.c_str()), sKey.length());
	hmac_sha256_update(&Ctx, reinterpret_cast<const unsigned char *>(sStringData.c_str()), sStringData.length());
	std::vector<unsigned char> MAC;
	MAC.resize(SHA256_DIGEST_SIZE);
	hmac_sha256_final(&Ctx, &MAC[0], SHA256_DIGEST_SIZE);
	return MAC;
}

std::vector<unsigned char> AWS::Auth::AWS4SignerBase::Sign(const std::string & sStringData, const std::vector<unsigned char> &Key)
{
	hmac_sha256_ctx Ctx;
	hmac_sha256_init(&Ctx, &Key[0], Key.size());
	hmac_sha256_update(&Ctx, reinterpret_cast<const unsigned char *>(sStringData.c_str()), sStringData.length());
	std::vector<unsigned char> MAC;
	MAC.resize(SHA256_DIGEST_SIZE);
	hmac_sha256_final(&Ctx, &MAC[0], SHA256_DIGEST_SIZE);
	return MAC;
}

void AWS::Auth::AWS4SignerBase::GetFormattedTimes(std::string &sDateTime, std::string &sDate)
{
	std::time_t t = std::time(nullptr);
	std::tm gtm;

	AWSgmtime(&gtm, &t);

	{
		std::stringstream Stream;
		//Stream << std::put_time(&gtm, "%Y%m%dT%H%M%S%z");
		Stream << std::put_time(&gtm, "%Y%m%dT%H%M%SZ");
		sDateTime = Stream.str();
		//Time = "20150823T094134Z";
	}
	
	{
		//"yyyyMMdd"
		std::stringstream Stream;
		Stream << std::put_time(&gtm, "%Y%m%d");
		sDate = Stream.str();
	}
}