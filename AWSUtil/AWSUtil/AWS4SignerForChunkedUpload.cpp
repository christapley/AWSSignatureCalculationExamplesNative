#include "stdafx.h"
#include "Auth.h"
#include <algorithm>

class AWS::Auth::AWS4SignerForChunkedUpload::Impl {
public:
	
	static std::string STREAMING_BODY_SHA256;

	static std::string CLRF;
	static std::string CHUNK_STRING_TO_SIGN_PREFIX;
	static std::string CHUNK_SIGNATURE_HEADER;
	static int SIGNATURE_LENGTH;
	static std::string FINAL_CHUNK;

	/**
	* Tracks the previously computed signature value; for chunk 0 this will
	* contain the signature included in the Authorization header. For
	* subsequent chunks it contains the computed signature of the prior chunk.
	*/
	std::string m_sLastComputedSignature;

	/**
	* Date and time of the original signing computation, in ISO 8601 basic
	* format, reused for each chunk
	*/
	std::string m_sDateTimeStamp;

	/**
	* The scope value of the original signing computation, reused for each chunk
	*/
	std::string m_sScope;

	/**
	* The derived signing key used in the original signature computation and
	* re-used for each chunk
	*/
	std::vector<unsigned char> m_SigningKey;

	Impl() :
		m_sLastComputedSignature(),
		m_sDateTimeStamp(),
		m_sScope(),
		m_SigningKey() {}
};

std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::STREAMING_BODY_SHA256 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CLRF = "\r\n";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CHUNK_STRING_TO_SIGN_PREFIX = "AWS4-HMAC-SHA256-PAYLOAD";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CHUNK_SIGNATURE_HEADER = ";chunk-signature=";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::FINAL_CHUNK = "";
int AWS::Auth::AWS4SignerForChunkedUpload::Impl::SIGNATURE_LENGTH = 64;



const std::string & AWS::Auth::AWS4SignerForChunkedUpload::StreamingBodySHA256()
{
	return AWS::Auth::AWS4SignerForChunkedUpload::Impl::STREAMING_BODY_SHA256;
}

AWS::Auth::AWS4SignerForChunkedUpload::AWS4SignerForChunkedUpload(
	const std::string &sEndpointUrl, 
	const std::string &sHttpMethod, 
	const std::string &sServiceName,
	const std::string &sRegionName) : 
	AWS4SignerBase(sEndpointUrl, sHttpMethod, sServiceName, sRegionName),
	m_pImpl(new Impl())
{

}

AWS::Auth::AWS4SignerForChunkedUpload::~AWS4SignerForChunkedUpload()
{
	if (m_pImpl) {
		delete m_pImpl;
		m_pImpl = NULL;
	}
}

std::string AWS::Auth::AWS4SignerForChunkedUpload::ComputeSignature(
	std::map<std::string, std::string> &Headers,
	std::map<std::string, std::string> &QueryParameters,
	const std::string &sBodyHash,
	const std::string &awsAccessKey,
	const std::string &awsSecretKey) 
{

	// first get the date and time for the subsequent request, and convert
	// to ISO 8601 format for use in signature generation
	std::string sDateStamp;
	AWS4SignerBase::GetFormattedTimes(m_pImpl->m_sDateTimeStamp, sDateStamp);

	// update the headers with required 'x-amz-date' and 'host' values
	Headers["x-amz-date"] = m_pImpl->m_sDateTimeStamp;

	const std::string &sEndPointURL = EndPointURL();
	std::string sHostHeader = Util::URIUtils::GetHostName(sEndPointURL);
	Headers["Host"] = sHostHeader;

	// canonicalize the headers; we need the set of header names as well as the
	// names and values to go into the signature process
	std::string sCanonicalizedHeaderNames = GetCanonicalizedHeaderNames(Headers);
	std::string sCanonicalizedHeaders = GetCanonicalizedHeaderString(Headers);

	// if any query string parameters have been supplied, canonicalize them
	std::string sCanonicalizedQueryParameters = GetCanonicalizedQueryString(QueryParameters);

	const std::string &sHTTPMethod = AWS4SignerBase::HTTPMethod();
	const std::string &sTerminator = AWS4SignerBase::Terminator();
	const std::string &sAlgorithm = AWS4SignerBase::Algorithm();
	const std::string &sScheme = AWS4SignerBase::Scheme();
	const std::string &sRegionName = AWS4SignerBase::RegionName();
	const std::string &sServiceName = AWS4SignerBase::ServiceName();

	// canonicalize the various components of the request
	std::string sCanonicalRequest = GetCanonicalRequest(sEndPointURL, sHTTPMethod,
		sCanonicalizedQueryParameters, sCanonicalizedHeaderNames,
		sCanonicalizedHeaders, sBodyHash);
		
	// construct the string to be signed
	m_pImpl->m_sScope = sDateStamp + "/" + sRegionName + "/" + sServiceName + "/" + sTerminator;
	std::string sStringToSign = GetStringToSign(sScheme, sAlgorithm, m_pImpl->m_sDateTimeStamp, m_pImpl->m_sScope, sCanonicalRequest);
		
	// compute the signing key
	std::string sSecret = sScheme;
	sSecret.append(awsSecretKey);
	std::vector<unsigned char> Digest = Sign(sDateStamp, sSecret);
	Digest = Sign(sRegionName, Digest);
	Digest = Sign(sServiceName, Digest);
	m_pImpl->m_SigningKey = Sign(sTerminator, Digest);
	Digest = Sign(sStringToSign, m_pImpl->m_SigningKey);

	// cache the computed signature ready for chunk 0 upload
	m_pImpl->m_sLastComputedSignature = Util::BinaryUtils::ToHex(Digest);

	std::string sCredentialsAuthorizationHeader =
		"Credential=" + awsAccessKey + "/" + m_pImpl->m_sScope;
	std::string sSignedHeadersAuthorizationHeader =
		"SignedHeaders=" + sCanonicalizedHeaderNames;
	std::string sSignatureAuthorizationHeader =
		"Signature=" + m_pImpl->m_sLastComputedSignature;

	std::string sAuthorizationHeader = sScheme + "-" + sAlgorithm + " "
		+ sCredentialsAuthorizationHeader + ", "
		+ sSignedHeadersAuthorizationHeader + ", "
		+ sSignatureAuthorizationHeader;

	return sAuthorizationHeader;
}

int64_t AWS::Auth::AWS4SignerForChunkedUpload::CalculateChunkedContentLength(int64_t nOriginalLength, int64_t nChunkSize)
{
	if (nOriginalLength <= 0) {
		throw new std::exception("Nonnegative content length expected.");
	}

	int64_t nMaxSizeChunks = nOriginalLength / nChunkSize;
	int64_t nRemainingBytes = nOriginalLength % nChunkSize;
	return nMaxSizeChunks * CalculateChunkHeaderLength(nChunkSize)
		+ (nRemainingBytes > 0 ? CalculateChunkHeaderLength(nRemainingBytes) : 0)
		+ CalculateChunkHeaderLength(0);
}

size_t AWS::Auth::AWS4SignerForChunkedUpload::ConstructSignedChunk(size_t nMaxChunkSize, size_t nUserDataLen, const void *pUserData, std::vector<unsigned char> &SignedChunk)
{
	std::stringstream ssChunkHeader(std::stringstream::out);

	// nonsig-extension; we have none in these samples
	std::string sNonsigExtension;
	size_t nChunkLength = 0;

	// if this is the first chunk, we package it with the signing result
	// of the request headers, otherwise we use the cached signature
	// of the previous chunk

	// sig-extension
	std::string sChunkStringToSign =
		Impl::CHUNK_STRING_TO_SIGN_PREFIX + "\n" +
		m_pImpl->m_sDateTimeStamp + "\n" +
		m_pImpl->m_sScope + "\n" +
		m_pImpl->m_sLastComputedSignature + "\n" +
		AWS4SignerBase::Hash(sNonsigExtension) + "\n";
	
	if (nUserDataLen == 0) {
		sChunkStringToSign += AWS4SignerBase::Hash(Impl::FINAL_CHUNK);
		std::string sHexLength = Util::BinaryUtils::ToHexString<size_t>(Impl::FINAL_CHUNK.size());
		ssChunkHeader << sHexLength;
	}
	else {
		nChunkLength = std::min(nMaxChunkSize, nUserDataLen);
		sChunkStringToSign += AWS4SignerBase::Hash(static_cast<const char *>(pUserData), 0, nChunkLength);
		std::string sHexLength = Util::BinaryUtils::ToHexString<size_t>(nChunkLength);
		ssChunkHeader << sHexLength;
	}
	
		

	// compute the V4 signature for the chunk
	std::string sChunkSignature = Util::BinaryUtils::ToHex(AWS4SignerBase::Sign(sChunkStringToSign, m_pImpl->m_SigningKey));

	// cache the signature to include with the next chunk's signature computation
	m_pImpl->m_sLastComputedSignature = sChunkSignature;

	// construct the actual chunk, comprised of the non-signed extensions, the
	// 'headers' we just signed and their signature, plus a newline then copy
	// that plus the user's data to a payload to be written to the request stream
	ssChunkHeader << sNonsigExtension << Impl::CHUNK_SIGNATURE_HEADER << sChunkSignature << Impl::CLRF;
	
	std::string sChunkHeader = ssChunkHeader.str();

	SignedChunk.clear();
	SignedChunk.resize(sChunkHeader.length() + nChunkLength + Impl::CLRF.length());
		
	memcpy(&SignedChunk[0], sChunkHeader.c_str(), sChunkHeader.length());
	memcpy(&SignedChunk[sChunkHeader.length()], pUserData, nChunkLength);
	memcpy(&SignedChunk[sChunkHeader.length() + nChunkLength], Impl::CLRF.c_str(), Impl::CLRF.length());

	return nChunkLength;
}

int64_t AWS::Auth::AWS4SignerForChunkedUpload::CalculateChunkHeaderLength(int64_t nChunkDataSize)
{
	std::string sHex = Util::BinaryUtils::ToHexString<int64_t>(nChunkDataSize);

	return sHex.length()
		+ Impl::CHUNK_SIGNATURE_HEADER.length()
		+ Impl::SIGNATURE_LENGTH
		+ Impl::CLRF.length()
		+ nChunkDataSize
		+ Impl::CLRF.length();
}
