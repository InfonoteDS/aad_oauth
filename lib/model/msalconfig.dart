/// Microsoft identity platform authentication library.
library msauth;

import 'dart:js_interop';

/// Interop with JS, we need to convert Config to a JS object or it comes
/// through as empty when passed to JS.
///
/// Parameters according to official Microsoft Documentation:
/// - Azure AD https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
/// - Azure AD B2C: https://docs.microsoft.com/en-us/azure/active-directory-b2c/authorization-code-flow
///
/// DartDocs of parameters are mostly from those pages.
///
/// Write-only: constructed and passed straight into the JS `init` call,
/// never read back from Dart — so this only needs the factory constructor,
/// no external getters.
extension type MsalConfig._(JSObject _) implements JSObject {
  /// Azure AD OAuth Configuration — see the class doc comment above for the
  /// Microsoft documentation links describing these parameters. Previously
  /// documented per-field, but extension types can't declare instance
  /// fields (only external members on the underlying JSObject), so the
  /// per-field doc comments were dropped rather than kept somewhere
  /// disconnected from the parameters they describe.
  external factory MsalConfig.construct(
      {String? tenant,
      String? policy,
      String? clientId,
      String? responseType,
      String? redirectUri,
      String? scope,
      String? responseMode,
      String? state,
      String? prompt,
      String? codeChallenge,
      String? codeChallengeMethod,
      String? nonce,
      String? tokenIdentifier,
      String? clientSecret,
      String? resource,
      bool? isB2C,
      String? customAuthorizationUrl,
      String? customTokenUrl,
      String? loginHint,
      String? domainHint,
      String? codeVerifier,
      String? authorizationUrl,
      String? tokenUrl,
      String? cacheLocation,
      String? customParameters,
      String? postLogoutRedirectUri});
}
