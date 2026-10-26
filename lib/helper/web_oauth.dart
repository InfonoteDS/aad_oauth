/// Microsoft identity platform authentication library.
/// @nodoc
@JS('aadOauth')
library msauth;

import 'dart:async';
import 'dart:convert';

import 'package:aad_oauth/helper/core_oauth.dart';
import 'package:aad_oauth/model/config.dart';
import 'package:aad_oauth/model/failure.dart';
import 'package:aad_oauth/model/msalconfig.dart';
import 'package:aad_oauth/model/token.dart';
import 'package:dartz/dartz.dart';
import 'dart:js_interop';

@JS('init')
external void jsInit(MsalConfig config);

@JS('login')
external void jsLogin(
  bool refreshIfAvailable,
  bool useRedirect,
  JSFunction onSuccess,
  JSFunction onError,
);

@JS('logout')
external void jsLogout(
  JSFunction onSuccess,
  JSFunction onError,
  bool showPopup,
);

@JS('getAccessToken')
external JSPromise<JSString?> jsGetAccessToken();

@JS('getIdToken')
external JSPromise<JSString?> jsGetIdToken();

@JS('hasCachedAccountInformation')
external bool jsHasCachedAccountInformation();

@JS('refreshToken')
external void jsRefreshToken(
  JSFunction onSuccess,
  JSFunction onError,
);

/// Reads a JS error-like value's `.message` property, if it has one — the
/// JS side (assets/msalv2.js) passes real `Error` objects to onError.
/// `dart:js_interop`'s typed callbacks don't dynamically proxy through to
/// the underlying JS object's own toString() the way the old loose
/// `dynamic`-based interop did, so a bare `.toString()` here would silently
/// show something unhelpful instead of the actual error message.
extension type _JSError._(JSObject _) implements JSObject {
  external JSString? get message;
}

String _jsErrorMessage(JSAny? error) {
  if (error != null && error.isA<JSObject>()) {
    final message = (error as _JSError).message;
    if (message != null) return message.toDart;
  }
  return error?.toString() ?? 'Unknown error';
}

class WebOAuth extends CoreOAuth {
  final Config config;
  WebOAuth(this.config) {
    jsInit(MsalConfig.construct(
        tenant: config.tenant,
        policy: config.policy,
        clientId: config.clientId,
        responseType: config.responseType,
        redirectUri: config.redirectUri,
        scope: config.scope,
        responseMode: config.responseMode,
        state: config.state,
        prompt: config.prompt,
        codeChallenge: config.codeChallenge,
        codeChallengeMethod: config.codeChallengeMethod,
        nonce: config.nonce,
        tokenIdentifier: config.tokenIdentifier,
        clientSecret: config.clientSecret,
        resource: config.resource,
        isB2C: config.isB2C,
        customAuthorizationUrl: config.customAuthorizationUrl,
        customTokenUrl: config.customTokenUrl,
        loginHint: config.loginHint,
        domainHint: config.domainHint,
        codeVerifier: config.codeVerifier,
        authorizationUrl: config.authorizationUrl,
        tokenUrl: config.tokenUrl,
        cacheLocation: config.cacheLocation.value,
        customParameters: jsonEncode(config.customParameters),
        postLogoutRedirectUri: config.postLogoutRedirectUri));
  }

  @override
  Future<String?> getAccessToken() async {
    final result = await jsGetAccessToken().toDart;
    return result?.toDart;
  }

  @override
  Future<String?> getIdToken() async {
    final result = await jsGetIdToken().toDart;
    return result?.toDart;
  }

  @override
  Future<bool> get hasCachedAccountInformation =>
      Future<bool>.value(jsHasCachedAccountInformation());

  @override
  Future<Either<Failure, Token>> login(
      {bool refreshIfAvailable = false}) async {
    final completer = Completer<Either<Failure, Token>>();

    jsLogin(
      refreshIfAvailable,
      config.webUseRedirect,
      // the JS side sends `accessToken ?? null`, so this must be nullable
      ((String? value) => completer.complete(Right(Token(accessToken: value)))).toJS,
      ((JSAny? error) => completer.complete(Left(AadOauthFailure(
            errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
            message:
                'Access denied or authentication canceled. Error: ${_jsErrorMessage(error)}',
          )))).toJS,
    );

    return completer.future;
  }

  @override
  Future<Either<Failure, Token>> refreshToken() {
    final completer = Completer<Either<Failure, Token>>();

    jsRefreshToken(
      ((String? value) => completer.complete(Right(Token(accessToken: value)))).toJS,
      ((JSAny? error) => completer.complete(Left(AadOauthFailure(
            errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
            message:
                'Access denied or authentication canceled. Error: ${_jsErrorMessage(error)}',
          )))).toJS,
    );

    return completer.future;
  }

  @override
  Future<void> logout({bool showPopup = true, bool clearCookies = true}) async {
    final completer = Completer<void>();

    jsLogout(
      (() => completer.complete()).toJS,
      ((JSAny error) => completer.completeError(error)).toJS,
      showPopup,
    );

    return completer.future;
  }
}

CoreOAuth getOAuthConfig(Config config) => WebOAuth(config);
