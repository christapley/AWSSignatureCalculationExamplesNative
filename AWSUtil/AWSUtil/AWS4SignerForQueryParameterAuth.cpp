#include "stdafx.h"
#include "Auth.h"

AWS::Auth::AWS4SignerForQueryParameterAuth::AWS4SignerForQueryParameterAuth(const std::string & sEndpointUrl, 
	const std::string & sHTTPMethod, 
	const std::string & sServiceName, 
	const std::string & sRegionName) : AWS4SignerBase(sEndpointUrl, sHTTPMethod, sServiceName, sRegionName)
{
}

std::string AWS::Auth::AWS4SignerForQueryParameterAuth::ComputeSignature(std::map<std::string, std::string> &Headers, std::map<std::string, std::string> &QueryParameters, const std::string &sBodyHash, const std::string & awsAccessKey, const std::string & awsSecretKey)
{
	// first get the date and time for the subsequent request, and convert
	// to ISO 8601 format
	// for use in signature generation

	std::string sTime, sDateStamp;
	AWS4SignerBase::GetFormattedTimes(sTime, sDateStamp);
	
	const std::string &EndPointURL = AWS4SignerBase::EndPointURL();
	std::string sHostName = AWS::Util::URIUtils::GetHostName(EndPointURL);

	Headers["Host"] = sHostName;

	// canonicalized headers need to be expressed in the query
	// parameters processed in the signature
	std::string sCanonicalizedHeaderNames = GetCanonicalizedHeaderNames(Headers);
	std::string sCanonicalizedHeaders = GetCanonicalizedHeaderString(Headers);

	const std::string &sTerminator = AWS4SignerBase::Terminator();
	const std::string &sAlgorithm = AWS4SignerBase::Algorithm();
	const std::string &sScheme = AWS4SignerBase::Scheme();
	const std::string &RegionName = AWS4SignerBase::RegionName();
	const std::string &ServiceName = AWS4SignerBase::ServiceName();
	const std::string &HTTPMethod = AWS4SignerBase::HTTPMethod();

	// we need scope as part of the query parameters
	std::string sScope = sDateStamp + "/" + RegionName + "/" + ServiceName + "/" + sTerminator;

	// add the fixed authorization params required by Signature V4
	QueryParameters["X-Amz-Algorithm"] = sScheme + "-" + sAlgorithm;
	QueryParameters["X-Amz-Credential"] = awsAccessKey + "/" + sScope;

	// x-amz-date is now added as a query parameter, but still need to be in ISO8601 basic form
	QueryParameters["X-Amz-Date"] = sTime;

	QueryParameters["X-Amz-SignedHeaders"] = sCanonicalizedHeaderNames;

	// build the expanded canonical query parameter string that will go into the
	// signature computation
	std::string sCanonicalizedQueryParameters = GetCanonicalizedQueryString(QueryParameters);

	// express all the header and query parameter data as a canonical request string
	std::string sCanonicalRequest = GetCanonicalRequest(EndPointURL, HTTPMethod,
		sCanonicalizedQueryParameters, sCanonicalizedHeaderNames,
		sCanonicalizedHeaders, sBodyHash);

	// construct the string to be signed
	std::string sStringToSign = GetStringToSign(sScheme, sAlgorithm, sTime, sScope, sCanonicalRequest);
	
	// compute the signing key
	std::string sSecret = sScheme;
	sSecret.append(awsSecretKey);
	std::vector<unsigned char> Digest = Sign(sDateStamp, sSecret);
	Digest = Sign(RegionName, Digest);
	Digest = Sign(ServiceName, Digest);
	Digest = Sign(sTerminator, Digest);
	Digest = Sign(sStringToSign, Digest);

	// form up the authorization parameters for the caller to place in the query string
	std::string sAuthString;
	sAuthString.append("X-Amz-Algorithm=" + QueryParameters["X-Amz-Algorithm"]);
	sAuthString.append("&X-Amz-Credential=" + QueryParameters["X-Amz-Credential"]);
	sAuthString.append("&X-Amz-Date=" + QueryParameters["X-Amz-Date"]);
	sAuthString.append("&X-Amz-Expires=" + QueryParameters["X-Amz-Expires"]);
	sAuthString.append("&X-Amz-SignedHeaders=" + QueryParameters["X-Amz-SignedHeaders"]);
	sAuthString.append("&X-Amz-Signature=" + AWS::Util::BinaryUtils::ToHex(Digest));

	return sAuthString;
}
