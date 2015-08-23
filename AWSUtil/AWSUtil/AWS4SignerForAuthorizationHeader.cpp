#include "stdafx.h"
#include "Auth.h"
#include "URIUtils.h"

AWS::Auth::AWS4SignerForAuthorizationHeader::AWS4SignerForAuthorizationHeader(
	const std::string & sEndpointUrl, 
	const std::string & sHttpMethod, 
	const std::string & sServiceName, 
	const std::string & sRegionName) : AWS4SignerBase(sEndpointUrl, sHttpMethod, sServiceName, sRegionName)
{

}

std::string AWS::Auth::AWS4SignerForAuthorizationHeader::ComputeSignature(
	std::map<std::string, std::string>& Headers, 
	const std::map<std::string, std::string>& QueryParameters, 
	const std::string & sBodyHash, 
	const std::string & awsAccessKey, 
	const std::string & awsSecretKey)
{
	std::string sTime, sDateStamp;
	AWS4SignerBase::GetFormattedTimes(sTime, sDateStamp);
	
	// update the headers with required 'x-amz-date' and 'host' values
	Headers["x-amz-date"] = sTime;

	const std::string &EndPointURL = AWS4SignerBase::EndPointURL();
	std::string sHostName = AWS::Util::URIUtils::GetHostName(EndPointURL);

	Headers["Host"] = sHostName;

	// canonicalize the headers; we need the set of header names as well as the
	// names and values to go into the signature process
	std::string sCanonicalizedHeaderNames = GetCanonicalizedHeaderNames(Headers);
	std::string sCanonicalizedHeaders = GetCanonicalizedHeaderString(Headers);

	// if any query string parameters have been supplied, canonicalize them
	std::string sCanonicalizedQueryParameters = GetCanonicalizedQueryString(QueryParameters);

	const std::string &HTTPMethod = AWS4SignerBase::HTTPMethod();

	// canonicalize the various components of the request
	std::string CanonicalRequest = GetCanonicalRequest(EndPointURL, HTTPMethod,
		sCanonicalizedQueryParameters, sCanonicalizedHeaderNames,
		sCanonicalizedHeaders, sBodyHash);

	// construct the string to be signed

	
	const std::string &sTerminator = AWS4SignerBase::Terminator();
	const std::string &sAlgorithm = AWS4SignerBase::Algorithm();
	const std::string &sScheme = AWS4SignerBase::Scheme();
	const std::string &RegionName = AWS4SignerBase::RegionName();
	const std::string &ServiceName = AWS4SignerBase::ServiceName();

	std::string sScope = sDateStamp + "/" + RegionName + "/" + ServiceName + "/" + sTerminator;
	std::string sStringToSign = GetStringToSign(sScheme, sAlgorithm, Time, sScope, CanonicalRequest);

	// compute the signing key
	std::string sSecret = sScheme;
	sSecret.append(awsSecretKey);
	std::vector<unsigned char> Digest = Sign(sDateStamp, sSecret);
	Digest = Sign(RegionName, Digest);
	Digest = Sign(ServiceName, Digest);
	Digest = Sign(sTerminator, Digest);
	Digest = Sign(sStringToSign, Digest);

	std::string sCredentialsAuthorizationHeader = "Credential=" + awsAccessKey + "/" + sScope;
	std::string sSignedHeadersAuthorizationHeader = "SignedHeaders=" + sCanonicalizedHeaderNames;
	std::string sSignatureAuthorizationHeader = "Signature=" + AWS::Util::BinaryUtils::ToHex(Digest);

	std::string sAuthorizationHeader = sScheme + "-" + sAlgorithm + " "
		+ sCredentialsAuthorizationHeader + ", "
		+ sSignedHeadersAuthorizationHeader + ", "
		+ sSignatureAuthorizationHeader;

	return sAuthorizationHeader;
}

