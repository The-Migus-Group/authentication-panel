# Solid-OIDC Authentication Spec - Draft

# Abstract

A key challenge on the path toward re-decentralizing user data on the Worldwide Web is the need to
access multiple potentially untrusted resources servers securely. This document aims to address that
challenge by building on top of current and future web standards, to allow entities to authenticate
within a distributed ecosystem.

# Status of This Document

This section describes the status of this document at the time of its publication. Other documents
may supersede this document. A list of current W3C publications and the latest revision of this
technical report can be found in the [W3C technical reports index](https://www.w3.org/TR/) at
https://www.w3.org/TR/.

This document is produced from work by
the [Solid Community Group](https://www.w3.org/community/solid/). It is a draft document that may,
or may not, be officially published. It may be updated, replaced, or obsoleted by other documents at
any time. It is inappropriate to cite this document as anything other than work in progress. The
source code for this document is available at the following
URI: <https://github.com/solid/authentication-panel>

This document was published by the
[Solid Authentication Panel](https://github.com/solid/process/blob/master/panels.md#authentication)
as a First Draft.

[GitHub Issues](https://github.com/solid/authentication-panel/issues) are preferred for discussion
of this specification. Alternatively, you can send comments to our mailing list. Please send them to
[public-solid@w3.org](mailto:public-solid@w3.org)
([archives](https://lists.w3.org/Archives/Public/public-solid/))

# Introduction

_This section is non-normative_

The [Solid project](https://solidproject.org/) aims to change the way web applications work today to
improve privacy and user control of personal data by utilizing current standards, protocols, and
tools, to facilitate building extensible and modular decentralized applications based on
[Linked Data](https://www.w3.org/standards/semanticweb/data) principles.

This specification is written for Authorization and Resource Server owners intending to implement
Solid-OIDC. It is also useful to Solid application developers charged with implementing a Solid-OIDC
client.

The [OAuth 2.0](https://tools.ietf.org/html/rfc6749) and
[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) web standards were
published in October 2012, and November 2014, respectively. Since publication, they have increased
with a marked pace and have claimed wide adoption with extensive _'real-world'_ data and experience.
The strengths of the protocols are now clear, however, in a changing eco-system where privacy and
control of digital identities are becoming more pressing concerns, it is also clear that additional
functionality is required.

The additional functionality is aimed at addressing:

1. Ephemeral clients as a common use case.
2. Resource servers with no existing trust relationship with identity providers.

## Out of Scope

_This section is non-normative_

At the time of writing, there is no demonstrated use case for a strongly asserted identity, however,
it is likely that authorization requirements will necessitate it.

# Terminology

_This section is non-normative_

This specification uses the terms "access token", "authorization server", "resource server" (RS),
"authorization endpoint", "token endpoint", "grant type", "access token reques", "access token
response", and "client" defined by The OAuth 2.0 Authorization Framework
\[[RFC6749](https://tools.ietf.org/html/rfc6749)\].

Throughout this specification, we will use the term Identity Provider (IdP) in line with the
terminology used in the
[Open ID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html)
(OIDC). It should be noted that
[The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) (OAuth) refers to this
same entity as an Authorization Server.

This specification also defines the following terms:

**WebID** _as defined in the
[WebID 1.0 Editors Draft](https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/identity-respec.html)_

A WebID is a URI with an HTTP or HTTPS scheme which denotes an Agent (Person, Organization, Group,
Device, etc.)

**JSON Web Token (JWT)** _as defined by [RFC7519](https://tools.ietf.org/html/rfc7519)_

A string representing a set of claims as a JSON object that is encoded in a JWS or JWE, enabling the
claims to be digitally signed or MACed and/or encrypted.

**JSON Web Key (JWK)** _as defined by [RFC7517](https://tools.ietf.org/html/rfc7517)_

A JSON object that represents a cryptographic key. The members of the object represent properties of
the key, including its value.

**Demonstration of Proof-of-Possession at the Application Layer (DPoP)** _as defined in the
[DPoP Internet-Draft](https://tools.ietf.org/html/draft-fett-oauth-dpop-04)_

A mechanism for sender-constraining OAuth tokens via a proof-of-possession mechanism on the
application level.

**DPoP Proof** _as defined by
[DPoP Internet-Draft](https://tools.ietf.org/html/draft-fett-oauth-dpop-04)_

A DPoP proof is a JWT that is signed (using JWS) using a private key chosen by the client.

**Proof Key for Code Exchange (PKCE)** _as defined by
[RFC7636](https://tools.ietf.org/html/rfc7636)_

An extension to the Authorization Code flow which mitigates the risk of an authorization code
interception attack.

**International Resource Identifier (IRI)** as defined by TODO:

# Conformance

_This section is non-normative_

All authoring guidelines, diagrams, examples, and notes in this document are non-normative.
Everything else in this specification is normative unless explicitly expressed otherwise.

The key words MAY, MUST, MUST NOT, RECOMMENDED, SHOULD, SHOULD NOT, and REQUIRED in this document
are to be interpreted as described in [BCP 14](https://tools.ietf.org/html/bcp14)
\[[RFC2119](https://www.w3.org/TR/2014/REC-cors-20140116/#refsRFC2119)\]
\[[RFC8174](https://www.w3.org/TR/2019/REC-vc-data-model-20191119/#bib-rfc8174)\] when, and only
when, they appear in all capitals, as shown here.

# Core Concepts

_This section is non-normative_

In a decentralized ecosystem, such as Solid, an IdP may be a preexisting IdP or vendor, or at the
other end of the spectrum, a user-controlled IdP.

Therefore, this specification makes extensive use of OAuth and OIDC best practices and assumes the
[Authorization](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps) Code Flow with
PKCE, as per OIDC definition. It is also assumed that there is no preexisting trust relationship
with the IdP. This means dynamic, and static client registration is entirely optional.

## WebIDs

_This section is non-normative_

In line with Linked Data principles, a
[WebID](https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/identity-respec.html) is a HTTP URI that,
when dereferenced, resolves to a profile document that is structured data in an
[RDF format](https://www.w3.org/TR/2014/REC-rdf11-concepts-20140225/). This profile document allows
people to link with others to grant access to identity resources as they see fit. WebIDs are an
underpinning principle of the Solid movement and are used as a primary identifier for users and
client applications in this specification.

# Basic Flow

_This section is non-normative_

> TODO: Add diagram.

The basic authentication and authorization flow is as follows:

1. The client requests a non-public resource from the RS.
2. The RS returns a 401 with a `WWW-Authenticate` HTTP header containing parameters that inform the
   client that a DPoP-bound Access Token is required.
3. The client presents its WebID to the IdP and requests an Authorization Code.
4. The client presents the Authorization Code and a DPoP proof, to the token endpoint.
5. The Token Endpoint returns a DPoP-bound Access Token and OIDC ID Token, to the client.
6. The client presents the DPoP-bound Access Token and DPoP proof, to the RS.
7. The RS validates the Access Token and DPoP header, then returns the requested resource.

# Client Identifiers

_This section is non-normative_

OAuth and OIDC flows require client applications to obtain a
[client identifier](https://tools.ietf.org/html/rfc6749#section-2.2) in the form of a `client_id`
claim. In order to reduce the burden of implementing Solid OIDC on existing IdPs, and to be
compliant with current best practices for Oauth and OIDC, a client identifier remains the key
mechanism in which an IdP and an RS can identify and determine the trustworthiness of the client
application. Below are three supported methods in which client applications may identify themselves
when requesting resources.

## WebID Document

A client MAY use its WebID as the client identifier.

When using this method, the WebID document MUST inlude the `solid:oidcRegistration` property. This
property and the RDF object MUST be a JSON serialization of an OIDC client registration, using the
definition of client registration metadata from \[[RFC7591](https://tools.ietf.org/html/rfc7591)\].
A client WebID SHOULD only list a single registration.

If an IdP supports client WebID negotiation, it MUST derefernce the client's WebID document and MUST
match any client-supplied parameters with the values in the client's WebID document. For example,
the `redirect_uri` provided by a client MUST be included in the registration `redirect_uris` list.

A successfully created Access Token MUST include the client's WebID in the `client_id` claim.

An example de-refenced document (as [Turtle](https://www.w3.org/TR/turtle/)) for the client WebID:
`https://app.example/webid#id`

```
@prefix solid: <http://www.w3.org/ns/solid/terms#> .

<#id> solid:oidcRegistration """{
    "client_id" : "https://app.example/webid#id",
    "client_secret" : "...",
    "client_secret_expires_at" : 0,
    "client_id_issued_at" : 1597375004,
    "redirect_uris" : ["https://app.example/callback"],
    "client_name" : "Solid Application Name",
    "client_uri" : "https://app.example/",
    "logo_uri" : "https://app.example/logo.png",
    "tos_uri" : "https://app.example/tos.html",
    "token_endpoint_auth_method" : "client_secret_basic",
    "scope" : "openid profile offline_access",
    "grant_types" : ["refresh_token","authorization_code"],
    "response_types" : ["code"],
    "default_max_age" : 60000,
    "require_auth_time" : true
    }""" .
```

## Public Identifier

For clients that wish to remain truely ephemeral, an alternative public identifier of
`http://www.w3.org/ns/solid/terms#PublicOidcClient` MAY be used.

If an IdP supports this isdentifier, any `redirect_uri` supplied SHOULD be accepted as valid. In
this instance the IdP SHOULD NOT defeference the remote IRI.

All Access Tokens with this identifier MUST be treated as anonymous clients by the RS.

## Dynamic Registration

In addition to the two methods above, clients MAY use standard OIDC dynamic or static registration.

All Access Tokens generated in this way are NOT REQUIRED to include the `client_id` claim. As such,
an RS should treat this category of Access Tokens as originating from an anonymous clients.

# Token Instantiation

Assuming the token request and DPoP Proof are valid, the client MUST receive two tokens from the
IdP:

1. A DPoP-bound Access Token
2. An OIDC ID Token

These tokens require additional and/or modified claims for them to be compliant with the
authorization flow laid out in this document.

## Access Token

The client MUST send the IdP a DPoP proof that is valid according to the
[DPoP Internet-Draft](https://tools.ietf.org/html/draft-fett-oauth-dpop-04).

The audience (`aud`) claim is REQUIRED for this flow, however, the DPoP token provides the full URL
of the request, making the `aud` claim redundant, so in Solid-OIDC the `aud` claim MUST be a string
with the value of `solid`.

An example Access Token:

```js
{
    "sub": "https://janedoe.com/web#id", // Web ID of User
    "iss": "https://idp.example.com",
    "aud": "solid",
    "iat": 1541493724,
    "exp": 1573029723, // Identity credential expiration (separate from the ID token expiration)
    "cnf":{
      "jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" // DPoP public key confirmation claim
    },
}
```

## ID Token

The subject (`sub`) claim in the returning ID Token MUST be set to the user's WebID.

Example:

```js
{
    "iss": "https://idp.example.com",
    "sub": "https://janedoe.com/web#id",
    "aud": "https://client.example.com",
    "nonce": "n-0S6_WzA2Mj",
    "exp": 1311281970,
    "iat": 1311280970,
}
```

# Resource Access

Ephemeral clients MUST use DPoP-bound Access Tokens.

## DPoP Validation

If a `cnf` claim is present in the Access Token, then it must a DPoP Proof must be present and
validated using the methods outlined in the
[DPoP Internet-Draft](https://tools.ietf.org/html/draft-fett-oauth-dpop-04#section-4.2).

As defined, this includes ensuring that the DPoP Proof has not expired, and both the URL and the
HTTP method match that of the requested resource. If any of these checks fail, the RS MUST deny the
resource request.

## Validating the Access Token

The public key in the fingerprint of the Access Token MUST be checked against the DPoP fingerprint
to ensure a match, as outlined in the
[DPoP Internet-Draft](https://tools.ietf.org/html/draft-fett-oauth-dpop-04#section-6).

### WebID

The `sub` claim of the Access Token MUST be a WebID. This needs to be dereferenced and checked
against the `iss` claim in the Access Token. If the `iss` claim is different from the domain of the
WebID, then the RS MUST check the WebID document for a `solid:oidcIssuer` property to check the
token issuer is listed. This prevents a malicious identity provider from issuing valid Access Tokens
for arbitrary WebIDs.

# Security Considerations

_This section is non-normative_

As this specification builds upon existing web standards, security considerations from OAuth, OIDC,
PKCE, and the DPoP specifications may also apply unless otherwise indicated. The following
considerations should be reviewed by implementors and system/s architects of this specification.

## TLS Requirements

All TLS requirements outlined in [BCP195](https://tools.ietf.org/html/bcp195) apply to this
specification.

All tokens, client, and user credentials MUST only be transmitted over TLS.

## Client IDs

Implementors SHOULD expire client IDs that are kept in server storage to mitigate the potential for
a bad actor to fill server storage with unexpired or otherwise useless client IDs.

## Client Secrets

Client secrets SHOULD NOT be stored in browser local storage. Doing so will increase the risk of
data leaks should an attacker gain access to client credentials.

## Client Trust

_This section is non-normative_

Clients are ephemeral, client registration is optional, and most clients cannot keep secrets. These,
among other factors, are what makes client trust challenging.

# Privacy Considerations

_This section is non-normative_

## Access Token Reuse

With JWTs being extendable by design, there is potential for a privacy breach if Access Tokens get
reused across multiple resource servers. It is not unimaginable that a custom claim is added to the
Access Token on instantiation. This addition may unintentionally give other resource servers
consuming the Access Token information about the user that they may not wish to share outside of the
intended RS.

# Acknowledgments

_This section is non-normative_

The Solid Community Group would like to thank the following individuals for reviewing and providing
feedback on the specification (in alphabetical order):

Tim Berners-Lee, Justin Bingham, Sarven Capadisli, Aaron Coburn, Matthias Evering, Jamie Fiedler,
Michiel de Jong, Ted Thibodeau Jr, Kjetil Kjernsmo, Pat McBennett, Adam Migus, Jackson Morgan, Davi
Ottenheimer, Justin Richer, severin-dsr, Henry Story, Michael Thornburgh, Emmet Townsend, Ruben
Verborgh, Ricky White, Paul Worrall, Dmitri Zagidulin.

# References

> TODO:
