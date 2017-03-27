'use strict';

(function () {

    let eventPrefix = 'oidcauth:';

    let unauthorizedEvent = eventPrefix + 'unauthorized';
    let tokenExpiredEvent = eventPrefix + 'tokenExpired';
    let tokenMissingEvent = eventPrefix + 'tokenMissing';
    let tokenExpiresSoonEvent = eventPrefix + 'tokenExpires';

    let loggedInEvent = eventPrefix + 'loggedIn';
    let loggedOutEvent = eventPrefix + 'loggedOut';

    let silentRefreshStartedEvent = eventPrefix + 'silentRefreshStarted';
    let silentInitRefreshStartedEvent = eventPrefix + 'silentInitRefreshStarted';
    let silentRefreshSuceededEvent = eventPrefix + 'silentRefreshSucceded';
    let silentRefreshFailedEvent = eventPrefix + 'silentRefreshFailed';

    let logger = {
        name: '[oidcauth]',
        make_log: function(handler, arg) {
            handler(...[logger.name, ...arg])
        },
        info: function(...args){
            logger.make_log(console.info, args)
        },
        debug: function(...args){
            logger.make_log(console.debug, args)
        },
        error: function(...args){
            logger.make_log(console.error, args)
        },
        warn: function(...args){
            logger.make_log(console.warn, args)
        },
        log: function(...args){
            logger.make_log(console.info, args)
        }
    };

    // Module registrarion
    let oidcmodule = angular.module('oidc-angular', ['base64', 'ngStorage', 'ui.router']);

    oidcmodule.config(['$httpProvider', '$stateProvider', function ($httpProvider, $stateProvider) {
        $httpProvider.interceptors.push('oidcHttpInterceptor');

        // Register callback route
        $stateProvider.state('auth-callback', {
            url: '/auth/callback/?code&state',
            template: '',
            controller: ['$auth', '$stateParams', function ($auth, $stateParams) {
                logger.info('handling login-callback');
                $auth.handleSignInCallback($stateParams);
            }]
        }).state('auth-clear', {
            url: '/auth/clear',
            template: '',
            controller: ['$auth', function ($auth) {
                logger.info('handling logout-callback');
                $auth.handleSignOutCallback();
            }]
        });

        logger.info('callback routes registered.')
    }]);

    oidcmodule.factory('oidcHttpInterceptor', ['$rootScope', '$q', '$injector', 'tokenService', function ($rootScope, $q, $injector, tokenService) {
        return {

            'request': function (request) {
                const $auth = $injector.get('$auth');
                if ($auth.config.apiUrl.test(request.url)) {

                    let appendBearer = false;

                    if ($auth.config.enableRequestChecks) {
                        // Only append token when it's valid.
                        if (tokenService.hasToken()) {
                            if (tokenService.hasValidToken()) {
                                appendBearer = true;
                            }
                            else {
                                $rootScope.$broadcast(tokenExpiredEvent, {request: request});
                                logger.error(tokenExpiredEvent, {request: request});
                            }
                        }
                        else {
                            $rootScope.$broadcast(tokenMissingEvent, {request: request});
                            logger.error(tokenMissingEvent, {request: request});
                        }
                    }
                    else {
                        appendBearer = tokenService.hasToken();
                    }

                    if (appendBearer) {
                        let token = tokenService.getIdToken();
                        request.headers['Authorization'] = 'Bearer ' + token;
                    }
                }

                // do something on success
                return request;
            },

            'response': function (response) {
                return response;
            },

            'responseError': function (response) {
                const $auth = $injector.get('$auth');
                if ($auth.config.apiUrl.test(response.config.url)) {

                    if (response.status == 401) {
                        if (!tokenService.hasToken()) {
                            // There was probably no token attached, because there is none
                            $rootScope.$broadcast(tokenMissingEvent, {response: response});
                            logger.error(tokenMissingEvent, {response: response});
                        }
                        else if (!tokenService.hasValidToken()) {
                            // Seems the token is not valid anymore
                            $rootScope.$broadcast(tokenExpiredEvent, {response: response});
                            logger.error(tokenExpiredEvent, {response: response});
                        }
                        else {
                            // any other
                            $rootScope.$broadcast(unauthorizedEvent, {response: response});
                            logger.error(unauthorizedEvent, {response: response});
                        }
                    }
                }

                return $q.reject(response);
            }
        };
    }]);

    oidcmodule.service('tokenService', ['$base64', '$localStorage', function ($base64, $localStorage) {

        const service = this;
        const STORAGE_KEYS = {
            idToken: 'oidc:token:idToken',
            refreshToken: 'oidc:token:refreshToken',
            claims: 'oidc:token:claims'
        };

        const padBase64 = function (base64data) {
            while (base64data.length % 4 !== 0) {
                base64data += "=";
            }
            return base64data;
        };

        service.getPayloadFromRawToken = function (raw) {
            let tokenParts = raw.split(".");
            if (tokenParts.length != 3) {
                logger.error('Raw token does NOT have valid format.', raw)
            }
            return tokenParts[1];
        };

        service.deserializeClaims = function (raw) {
            try {
                let claimsBase64 = padBase64(raw);
                let claimsJson = $base64.decode(claimsBase64);

                return JSON.parse(claimsJson);
            } catch (e) {
                logger.error(e);
                return {}
            }
        };

        service.convertToClaims = function (id_token) {
            let payload = service.getPayloadFromRawToken(id_token);
            return service.deserializeClaims(payload);
        };

        service.getIdToken = function () {
            return $localStorage[STORAGE_KEYS.idToken];
        };
        service.getRefreshToken = function () {
            return $localStorage[STORAGE_KEYS.refreshToken];
        };

        service.saveIdToken = function (id_token) {
            $localStorage[STORAGE_KEYS.idToken] = id_token;
        };

        service.saveRefreshToken = function (refresh_token) {
            $localStorage[STORAGE_KEYS.refreshToken] = refresh_token;
        };

        service.saveTokens = function (id_token, refresh_token) {
            service.clearTokens();
            service.saveIdToken(id_token);
            service.saveRefreshToken(refresh_token);
        };

        service.hasToken = function () {
            let claims = service.allClaims();
            return claims && claims.hasOwnProperty("iat") && claims.hasOwnProperty('exp');
        };

        service.hasValidToken = function () {
            if (!this.hasToken()) return false;

            let claims = service.allClaims();
            if (!claims.hasOwnProperty('iat') || !claims.hasOwnProperty('exp')) {
                logger.error('Token claims does NOT have valid fields.', claims);
                return false
            }

            let now = Date.now();
            //noinspection JSUnresolvedVariable
            let issuedAtMSec = claims.iat * 1000;
            let expiresAtMSec = claims.exp * 1000;
            let marginMSec = 1000 * 60 * 5; // 5 Minutes

            // Substract margin, because browser time could be a bit in the past
            if (issuedAtMSec - marginMSec > now) {
                logger.log('Token is not yet valid!');
                return false
            }

            if (expiresAtMSec < now) {
                logger.log('Token has expired!');
                return false;
            }

            return true;
        };

        service.allClaims = function () {
            let cachedClaims = $localStorage[STORAGE_KEYS.claims];

            if (!cachedClaims) {
                let id_token = service.getIdToken();

                if (id_token) {
                    cachedClaims = service.convertToClaims(id_token);
                    $localStorage[STORAGE_KEYS.claims] = cachedClaims;
                }
            }
            return cachedClaims;
        };

        service.clearTokens = function () {
            delete $localStorage[STORAGE_KEYS.claims];
            delete $localStorage[STORAGE_KEYS.idToken];
            delete $localStorage[STORAGE_KEYS.refreshToken];
        }
    }]);

    //noinspection JSUnusedLocalSymbols
    oidcmodule.provider("$auth", [function() {
        const STORAGE_KEYS = {
            logoutActive: 'oidc:auth:logoutActive',
            refreshRunning: 'oidc:auth:refreshRunning',
            validateExpiryLoopRunning: 'oidc:auth:validateExpiryLoopRunning',
            localRedirect: 'oidc:auth:localRedirect',
            state: 'oidc:auth:state',
            nonce: 'oidc:auth:nonce',
            code_challenge: 'oidc:auth:code_challenge'
        };

        const getRandomString = (len) => {
            const arr = new Uint8Array(Math.floor((len || 40) / 2));
            //noinspection JSUnresolvedFunction
            window.crypto.getRandomValues(arr);
            const result = Array.from(arr).map(dec2hex).join('');
            logger.debug('[getRandomString]', result);
            return result;
        };

        // Default configuration
        let config = {
            basePath: '',
            clientId: '',
            apiUrl: '/api/',
            responseType: 'code',
            scope: "openid",
            redirectUri: (window.location.origin || window.location.protocol + '//' + window.location.host) + window.location.pathname + '#/auth/callback/',
            logoutUri: (window.location.origin || window.location.protocol + '//' + window.location.host) + window.location.pathname + '#/auth/clear',
            authorizationEndpoint: 'connect/authorize',
            endSessionEndpoint: 'connect/endsession',
            tokenEndpoint: 'connect/token',
            advanceRefresh: 300,
            enableRequestChecks: false,
            stickToLastKnownIdp: false
        };

        return {

            // Service configuration
            configure: function (params) {
                angular.extend(config, params);
                if (typeof config.apiUrl == 'string') {
                    config.apiUrl = new RegExp(config.apiUrl);
                }
            },

            // Service itself
            $get: ['$http', '$timeout', '$rootScope', '$localStorage', '$location', 'tokenService', '$httpParamSerializer', function (
                    $http,   $timeout,   $rootScope,   $localStorage,   $location,   tokenService,   $httpParamSerializer   ) {

                const setLogoutActiveFlag = () => $localStorage[STORAGE_KEYS.logoutActive] = true;
                const clearLogoutActiveFlag = () => delete $localStorage[STORAGE_KEYS.logoutActive];
                const isLogoutActiveFlag = () => $localStorage[STORAGE_KEYS.logoutActive];

                const setRefreshRunningFlag = () => $localStorage[STORAGE_KEYS.refreshRunning] = true;
                const clearRefreshRunningFlag = () => delete $localStorage[STORAGE_KEYS.refreshRunning];
                const isRefreshRunningFlag = () => $localStorage[STORAGE_KEYS.refreshRunning];

                const setExpiryLoopRunningFlag = () => $localStorage[STORAGE_KEYS.validateExpiryLoopRunning] = true;
                const clearExpiryLoopRunningFlag = () => delete $localStorage[STORAGE_KEYS.validateExpiryLoopRunning];
                const isExpiryLoopRunningFlag = () => $localStorage[STORAGE_KEYS.validateExpiryLoopRunning];

                const getState = function(){
                    if (!$localStorage[STORAGE_KEYS.state]) {
                        $localStorage[STORAGE_KEYS.state] = getRandomString(17);
                    }
                    return $localStorage[STORAGE_KEYS.state];
                };
                const clearState = () => delete $localStorage[STORAGE_KEYS.state];

                const getNonce = function(){
                    if (!$localStorage[STORAGE_KEYS.nonce]) {
                        $localStorage[STORAGE_KEYS.nonce] = getRandomString(17);
                    }
                    return $localStorage[STORAGE_KEYS.nonce];
                };
                const clearNonce = () => delete $localStorage[STORAGE_KEYS.nonce];

                const getCodeChallenge = function() {
                    if (!$localStorage[STORAGE_KEYS.code_challenge]){
                        $localStorage[STORAGE_KEYS.code_challenge] = getRandomString(17);
                    }
                    return $localStorage[STORAGE_KEYS.code_challenge]
                };
                const getHashedCodeChallenge = () => {
                    // const hashBytes = sha256.convertToSHA256(getCodeChallenge());
                    // logger.log('[hashBytes]', hashBytes, hashBytes.match(/.{2}/g));
                    // alert('d');
                    //
                    // return arrayBufferToBase64(hashBytes.match(/.{2}/g)).replace('=', '');
                    return getCodeChallenge();
                };

                const getCodeChallengeMethod = () => 'plain'; //'S256';
                const clearCodeChallenge = () => delete $localStorage[STORAGE_KEYS.code_challenge];

                const setLocalRedirect = (url) => $localStorage[STORAGE_KEYS.localRedirect] = url;
                const getLocalRedirect = () => $localStorage[STORAGE_KEYS.localRedirect];
                const clearLocalRedirect = () => delete $localStorage[STORAGE_KEYS.localRedirect];


                const init = function () {

                    if (isLogoutActiveFlag()) {
                        clearLogoutActiveFlag();
                        tokenService.clearTokens();
                    }

                    if (isRefreshRunningFlag()) {
                        clearRefreshRunningFlag();
                    }
                    if (isExpiryLoopRunningFlag()) {
                        clearExpiryLoopRunningFlag();
                    }
                    if (tokenService.hasToken()) {
                        if (tokenService.hasValidToken()) {
                            validateExpiryLoop();
                        } else {
                            $rootScope.$broadcast(silentInitRefreshStartedEvent);
                            logger.log(silentInitRefreshStartedEvent);
                            trySilentRefresh();
                        }
                    }
                };

                const validateExpiryLoop = function () {
                    if (isExpiryLoopRunningFlag()) {
                        return;
                    }
                    setExpiryLoopRunningFlag();
                    logger.info('Starting validateExpiryLoop');
                    let myLoop = function () {
                        if (!isExpiryLoopRunningFlag()) {
                            logger.info('Stopping validateExpiryLoop()');
                            return;
                        }
                        validateExpirity();
                        $timeout(myLoop, config.advanceRefresh * 1000);
                    };
                    myLoop();
                };

                const createLoginUrl = function () {
                    let targetUrl = '';

                    if (!config.authorizationEndpoint.startsWith('http://') && !config.authorizationEndpoint.startsWith('https://')) {
                        targetUrl += config.basePath;
                        targetUrl += targetUrl.endsWith('/')?'':'/';
                    }
                    targetUrl += config.authorizationEndpoint;

                    let currentClaims = tokenService.allClaims();
                    let idpClaimValue = currentClaims?currentClaims["idp"]:'';

                    let url = targetUrl
                        + "?response_type="
                        + encodeURIComponent(config.responseType)
                        + "&client_id="
                        + encodeURIComponent(config.clientId)
                        + "&state="
                        + encodeURIComponent(getState())
                        + "&nonce="
                        + encodeURIComponent(getNonce())
                        + "&code_challenge="
                        + encodeURIComponent(getHashedCodeChallenge())
                        + "&code_challenge_method="
                        + encodeURIComponent(getCodeChallengeMethod())
                        + "&redirect_uri="
                        + encodeURIComponent(config.redirectUri)
                        + "&scope="
                        + encodeURIComponent(config.scope);

                    if (config.stickToLastKnownIdp && idpClaimValue) {
                        url = url + "&acr_values="
                            + encodeURIComponent("idp:" + idpClaimValue);
                    }

                    return url;
                };

                const createTokenEndpointUrl = function() {
                    let targetUrl = '';

                    if (!config.tokenEndpoint.startsWith('http://') && !config.tokenEndpoint.startsWith('https://')) {
                        targetUrl += config.basePath;
                        targetUrl += targetUrl.endsWith('/') ? '' : '/';
                    }
                    targetUrl += config.tokenEndpoint;

                    return targetUrl;
                };

                const createCodeExchangePayload = function(code){
                    let code_challenge = getCodeChallenge();
                    clearCodeChallenge();
                    return {
                        grant_type: 'authorization_code',
                        client_id: config.clientId,
                        redirect_uri: config.redirectUri,
                        code: code,
                        code_verifier: code_challenge
                    };
                };

                const createTokenRefreshPayload = function(refresh_token){
                    return {
                        grant_type: 'refresh_token',
                        client_id: config.clientId,
                        refresh_token: refresh_token
                    };
                };

                const createLogoutUrl = function () {
                    clearState();

                    let targetUrl = '';

                    if (!config.endSessionEndpoint.startsWith('http://') && !config.endSessionEndpoint.startsWith('https://')) {
                        targetUrl += config.basePath;
                        targetUrl += targetUrl.endsWith('/')?'':'/';
                    }
                    targetUrl += config.endSessionEndpoint;

                    let idToken = tokenService.getIdToken();

                    return targetUrl
                        + "?id_token_hint="
                        + encodeURIComponent(idToken)
                        + "&post_logout_redirect_uri="
                        + encodeURIComponent(config.logoutUri)
                        + "&state="
                        + encodeURIComponent(getState())
                        + "&r=" + Math.random();
                };

                const startCodeFlow = function (localRedirect) {
                    clearCodeChallenge();
                    clearNonce();
                    clearState();
                    setLocalRedirect(localRedirect);
                    let url = createLoginUrl();
                    $timeout(()=>window.location.replace(url));
                };

                const startLogout = function () {
                    let url = createLogoutUrl();
                    setLogoutActiveFlag();
                    clearExpiryLoopRunningFlag();

                    $timeout(() => window.location.replace(url));
                };

                const handleCodeFlowCallback = function (id_token, refresh_token) {
                    tokenService.saveTokens(id_token, refresh_token);

                    let redirectTo, localRedirect = getLocalRedirect();

                    if (localRedirect) {
                        redirectTo = localRedirect.hash.substring(1);
                        clearLocalRedirect();
                    }
                    else {
                        redirectTo = '/';
                    }
                    if (tokenService.hasValidToken()) {
                        validateExpiryLoop();
                    }
                    $rootScope.$broadcast(loggedInEvent);
                    logger.log(loggedInEvent);
                    $timeout(()=>$location.path(redirectTo));
                    return true;
                };

                const handleSilentRefreshCallback = function (idToken, refreshToken) {
                    let currentClaims = tokenService.allClaims();
                    let event;
                    let newClaims = tokenService.convertToClaims(idToken);
                    let logHandler = logger.log;

                    if (!currentClaims || (currentClaims.exp && newClaims.exp && newClaims.exp > currentClaims.exp)) {
                        tokenService.saveTokens(idToken, refreshToken);
                        event = silentRefreshSuceededEvent;
                    }
                    else {
                        event = silentRefreshFailedEvent;
                        logHandler = logger.error;
                    }
                    if (tokenService.hasValidToken()) {
                        validateExpiryLoop();
                    }
                    clearRefreshRunningFlag();
                    $rootScope.$broadcast(event);
                    logHandler(event);
                };

                const trySilentRefresh = function () {

                    if (isRefreshRunningFlag()) {
                        logger.info('Refreshing is running. Aborting...');
                        return;
                    }
                    logger.log('Refreshing token...');
                    setRefreshRunningFlag();
                    $rootScope.$broadcast(silentRefreshStartedEvent);
                    logger.log(silentRefreshStartedEvent);

                    let refresh_token = tokenService.getRefreshToken();
                    $http.post(
                        createTokenEndpointUrl(),
                        $httpParamSerializer(createTokenRefreshPayload(refresh_token)),
                        {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded' // Note the appropriate header
                            }
                        }
                    ).then((response)=> {
                        let wrong_response = false;
                        if (!response.data.hasOwnProperty('id_token')) {
                            wrong_response = 'Code exchange response does NOT have "id_token"';
                        }
                        if (!response.data.hasOwnProperty('refresh_token')) {
                            wrong_response = 'Code exchange response does NOT have "refresh_token"';
                        }
                        if (wrong_response) {
                            logger.error(wrong_response, response.data);
                            $rootScope.$broadcast(silentRefreshFailedEvent);
                            clearRefreshRunningFlag();
                            return
                        }
                        handleSilentRefreshCallback(response.data.id_token, response.data.refresh_token)
                    }, (response)=> {
                        logger.error('Unable to perform silent Refresh', response.statusText, response.data);
                        $rootScope.$broadcast(silentRefreshFailedEvent);
                        clearRefreshRunningFlag();
                    });

                };

                const exchangeCodeForTokens = function(code) {
                    logger.info('Exchanging "code" for refresh token');

                    $http.post(
                        createTokenEndpointUrl(),
                        $httpParamSerializer(createCodeExchangePayload(code)),
                        {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded' // Note the appropriate header
                            }
                        }
                    ).then((response)=>{
                        let wrong_response = false;
                        if (!response.data.hasOwnProperty('id_token')) {
                            wrong_response = 'Code exchange response does NOT have "id_token"';
                        }
                        if (!response.data.hasOwnProperty('refresh_token')) {
                            wrong_response = 'Code exchange response does NOT have "refresh_token"';
                        }
                        if (wrong_response) {
                            logger.error(wrong_response, response.data);
                            throw new Error(wrong_response);
                        }
                        handleCodeFlowCallback(response.data.id_token, response.data.refresh_token);
                    }, (response) => {
                        let msg = 'Unable to exchange code for token!';
                        logger.error(msg, response.statusText, response);
                        throw new Error(msg);
                    })
                };


                const handleSignInCallback = function (data) {

                    logger.debug("Processing callback information", data);
                    if (!data.code && !data.state){
                        // workaround for bug https://github.com/angular/angular.js/issues/6172
                        const absUrl = $location.absUrl();
                        const start = absUrl.indexOf('?')+1;
                        const end = absUrl.indexOf('#');
                        const queryParams = absUrl.substr(start, end-start);
                        data = parseQueryString(queryParams);
                    }

                    const code = data.code;
                    const state = data.state;

                    if (getState() != state) {
                        let msg = 'Wrong STATE. CSRF detected.';
                        logger.error(msg, getState(), state);
                        throw new Error(msg);
                    }

                    exchangeCodeForTokens(code);
                };

                const handleSignOutCallback = function () {
                    clearLogoutActiveFlag();
                    clearExpiryLoopRunningFlag();

                    tokenService.clearTokens();

                    $rootScope.$broadcast(loggedOutEvent);
                    logger.log(loggedOutEvent);

                    $timeout(()=>{$location.path('/')});
                };

                const tokenIsValidAt = function (date) {
                    let claims = tokenService.allClaims();

                    if (!claims || !(claims.hasOwnProperty('exp'))) {
                        return false;
                    }

                    let expiresAtMSec = claims.exp * 1000;

                    return date <= expiresAtMSec;
                };

                const validateExpirity = function () {
                    let now = Date.now();

                    if (!tokenService.hasValidToken() || !tokenIsValidAt(now + config.advanceRefresh * 1000)) {
                        $rootScope.$broadcast(tokenExpiresSoonEvent);
                        logger.warn(tokenExpiresSoonEvent);
                        trySilentRefresh();
                    }
                };

                init();

                //noinspection JSUnusedGlobalSymbols
                return {
                    config: config,

                    handleSignInCallback: handleSignInCallback,

                    handleSignOutCallback: handleSignOutCallback,

                    validateExpirity: validateExpirity,

                    isAuthenticated: function () {
                        return tokenService.hasValidToken();
                    },

                    isAuthenticatedIn: function (milliseconds) {
                        return tokenService.hasValidToken() && tokenIsValidAt(new Date().getTime() + milliseconds);
                    },

                    signIn: function (localRedirect) {
                        startCodeFlow(localRedirect);
                    },

                    signOut: function () {
                        startLogout();
                    },

                    silentRefresh: function () {
                        trySilentRefresh();
                    }

                };
            }]
        };
    }]);

    /* Helpers & Polyfills */

    function arrayBufferToBase64(ab){

        let dView = new Uint8Array(ab);   //Get a byte view

        let arr = Array.prototype.slice.call(dView); //Create a normal array

        let arr1 = arr.map(function(item){
            return String.fromCharCode(item);    //Convert
        });

        return window.btoa(arr1.join(''));   //Form a string

    }


    if (!String.prototype.endsWith) {
        String.prototype.endsWith = function (searchString, position) {
            let subjectString = this.toString();
            if (position === undefined || position > subjectString.length) {
                position = subjectString.length;
            }
            position -= searchString.length;
            let lastIndex = subjectString.indexOf(searchString, position);
            return lastIndex !== -1 && lastIndex === position;
        };
    }

    if (!String.prototype.startsWith) {
        String.prototype.startsWith = function (searchString, position) {
            position = position || 0;
            return this.lastIndexOf(searchString, position) === position;
        };
    }

    function dec2hex (dec) {
        return ('0' + dec.toString(16)).substr(-2)
    }

    function arrayBufferToBase64(ab){

        let dView = new Uint8Array(ab);   //Get a byte view

        let arr = Array.prototype.slice.call(dView); //Create a normal array

        let arr1 = arr.map(function(item){
            return String.fromCharCode(item);    //Convert
        });

        return window.btoa(arr1.join(''));   //Form a string

    }

    function parseQueryString(queryString) {
        let data = {}, pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;

        if (queryString === null) {
            return data;
        }

        pairs = queryString.split("&");

        for (let i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf("=");

            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            } else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }

            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);

            if (key.substr(0, 1) === '/')
                key = key.substr(1);

            data[key] = value;
        }

        return data;
    }
})();
