#include "stdafx.h"
#include "Auth.h"

class AWS::Auth::AWS4SignerForChunkedUpload::Impl {
public:
	
	static std::string STREAMING_BODY_SHA256;

	static std::string CLRF;
	static std::string CHUNK_STRING_TO_SIGN_PREFIX;
	static std::string CHUNK_SIGNATURE_HEADER;
	static int SIGNATURE_LENGTH;
	//static byte[] FINAL_CHUNK = new byte[0];

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
	std::vector<unsigned char> SigningKey;

	Impl() :
		m_sLastComputedSignature(),
		m_sDateTimeStamp(),
		m_sScope(),
		SigningKey() {}
};

std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::STREAMING_BODY_SHA256 = "STREAMING_BODY_SHA256";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CLRF = "\r\n";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CHUNK_STRING_TO_SIGN_PREFIX = "AWS4-HMAC-SHA256-PAYLOAD";
std::string AWS::Auth::AWS4SignerForChunkedUpload::Impl::CHUNK_SIGNATURE_HEADER = ";chunk-signature=";
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

std::string AWS::Auth::AWS4SignerForChunkedUpload::ComputeSignature(
	std::map<std::string, std::string> &Headers,
	std::map<std::string, std::string> &QueryParameters,
	const std::string &sBodyHash,
	const std::string &awsAccessKey,
	const std::string &awsSecretKey) 
{

	// first get the date and time for the subsequent request, and convert
	// to ISO 8601 format for use in signature generation
	std::string sDateTimeStamp, sDateStamp;
	AWS4SignerBase::GetFormattedTimes(sDateTimeStamp, sDateStamp);

	// update the headers with required 'x-amz-date' and 'host' values
	Headers["x-amz-date"] = sDateTimeStamp;

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
	std::string sStringToSign = GetStringToSign(sScheme, sAlgorithm, sDateTimeStamp, m_pImpl->m_sScope, sCanonicalRequest);
		
	// compute the signing key
	std::string sSecret = sScheme;
	sSecret.append(awsSecretKey);
	std::vector<unsigned char> Digest = Sign(sDateStamp, sSecret);
	Digest = Sign(sRegionName, Digest);
	Digest = Sign(sServiceName, Digest);
	Digest = Sign(sTerminator, Digest);
	Digest = Sign(sStringToSign, Digest);

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

std::vector<unsigned char> AWS::Auth::AWS4SignerForChunkedUpload::ConstructSignedChunk(int nUserDataLen, std::vector<unsigned char> UserData)
{
	// to keep our computation routine signatures simple, if the userData
	// buffer contains less data than it could, shrink it. Note the special case
	// to handle the requirement that we send an empty chunk to complete
	// our chunked upload.
	std::vector<unsigned char> DataToChunk;
	return DataToChunk;
	//if (nUserDataLen > 0) {
	//	if (nUserDataLen < UserData.size()) {
	//		// shrink the chunkdata to fit
	//		DataToChunk.resize(nUserDataLen);
	//		memcpy(&DataToChunk[0], &UserData[0], nUserDataLen);
	//	}
	//	else {
	//		dataToChunk = userData;
	//	}
	//}

	//StringBuilder chunkHeader = new StringBuilder();

	//// start with size of user data
	//chunkHeader.append(Integer.toHexString(dataToChunk.length));

	//// nonsig-extension; we have none in these samples
	//String nonsigExtension = "";

	//// if this is the first chunk, we package it with the signing result
	//// of the request headers, otherwise we use the cached signature
	//// of the previous chunk

	//// sig-extension
	//String chunkStringToSign =
	//	CHUNK_STRING_TO_SIGN_PREFIX + "\n" +
	//	dateTimeStamp + "\n" +
	//	scope + "\n" +
	//	lastComputedSignature + "\n" +
	//	BinaryUtils.toHex(AWS4SignerBase.hash(nonsigExtension)) + "\n" +
	//	BinaryUtils.toHex(AWS4SignerBase.hash(dataToChunk));

	//// compute the V4 signature for the chunk
	//String chunkSignature = BinaryUtils.toHex(AWS4SignerBase.sign(chunkStringToSign, signingKey, "HmacSHA256"));

	//// cache the signature to include with the next chunk's signature computation
	//lastComputedSignature = chunkSignature;

	//// construct the actual chunk, comprised of the non-signed extensions, the
	//// 'headers' we just signed and their signature, plus a newline then copy
	//// that plus the user's data to a payload to be written to the request stream
	//chunkHeader.append(nonsigExtension + CHUNK_SIGNATURE_HEADER + chunkSignature);
	//chunkHeader.append(CLRF);

	//try {
	//	byte[] header = chunkHeader.toString().getBytes("UTF-8");
	//	byte[] trailer = CLRF.getBytes("UTF-8");
	//	byte[] signedChunk = new byte[header.length + dataToChunk.length + trailer.length];
	//	System.arraycopy(header, 0, signedChunk, 0, header.length);
	//	System.arraycopy(dataToChunk, 0, signedChunk, header.length, dataToChunk.length);
	//	System.arraycopy(trailer, 0,
	//		signedChunk, header.length + dataToChunk.length,
	//		trailer.length);

	//	// this is the total data for the chunk that will be sent to the request stream
	//	return signedChunk;
	//}
	//catch (Exception e) {
	//	throw new RuntimeException("Unable to sign the chunked data. " + e.getMessage(), e);
	//}
}

int64_t AWS::Auth::AWS4SignerForChunkedUpload::CalculateChunkHeaderLength(int64_t nChunkDataSize)
{
	std::stringstream ss(std::stringstream::out);
	ss << std::hex << nChunkDataSize;
	std::string sHex = ss.str();

	return sHex.length()
		+ Impl::CHUNK_SIGNATURE_HEADER.length()
		+ Impl::SIGNATURE_LENGTH
		+ Impl::CLRF.length()
		+ nChunkDataSize
		+ Impl::CLRF.length();
}
