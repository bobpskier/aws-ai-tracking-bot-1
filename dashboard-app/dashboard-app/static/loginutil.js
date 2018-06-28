/* eslint-disable prefer-template */

const CognitoAuth = AmazonCognitoIdentity.CognitoAuth;

const poolid = appIdentityPoolId;
const region = appRegion;
localStorage.setItem('poolid', poolid);
localStorage.setItem('awsregionname', region);
const token = localStorage.getItem('idtokenjwt');
const noauth = localStorage.getItem('noauth');
const rd1 = window.location.protocol + '//' + window.location.hostname + '/index.html?loggedin=yes';
const rd2 = window.location.protocol + '//' + window.location.hostname + '/index.html?loggedout=yes';

const processFitbitResponse = function (res) {
  if (!res.ok) {
    throw new Error('Fitbit API request failed: ' + res);
  }

  const contentType = res.headers.get('content-type');
  if (contentType && contentType.indexOf('application/json') !== -1) {
    const val = res.json();
    val.then((data) => {
      console.debug('fitbit returned: ' + JSON.stringify(data, null, 2));
      localStorage.setItem('fitbitdata', JSON.stringify(data, null, 2));
    });
    window.location.href = 'index.html?home';
  } else {
    throw new Error('JSON expected but received ' + contentType);
  }
};

const authData = {
  ClientId: appUserPoolClientId, // Your client id here
  AppWebDomain: appDomainName,
  TokenScopesArray: ['email', 'openid', 'profile'],
  RedirectUriSignIn: rd1,
  RedirectUriSignOut: rd2,
};

/* eslint-disable prefer-template, object-shorthand, prefer-arrow-callback */

const auth = new CognitoAuth(authData);

function logout() {
  localStorage.removeItem('idtokenjwt');
  if (noauth === 'true') {
    window.location.href = '/static/indexentry.html';
  } else {
    auth.signOut();
    auth.clearCachedTokensScopes();
    localStorage.removeItem('aws.cognito.identity-id.' + poolid);
  }
}

auth.userhandler = {
  onSuccess: function () {
    console.debug('Sign in success');
  },
  onFailure: function (err) {
    console.debug('Sign in failure: ' + JSON.stringify(err, null, 2));
  },
};

const curUrl = window.location.href;
if (curUrl.indexOf('home') >= 0) {
  localStorage.setItem('username', auth.getUsername());
  if (token === null || token === undefined) {
    auth.getSession();
  } else {
    console.debug('goto home');
    const session = auth.getSignInUserSession();
    if (!session.isValid()) {
      auth.getSession();
    }
  }
} else if (curUrl.indexOf('noauth') >= 0) {
  localStorage.setItem('noauth', 'true');
  localStorage.removeItem('idtokenjwt');
} else if (curUrl.indexOf('loggedin') >= 0) {
  const values = curUrl.split('?');
  const minurl = '/' + values[1];
  try {
    auth.parseCognitoWebResponse(minurl);
    const idToken = auth.getSignInUserSession().getIdToken();
    const accessToken = auth.getSignInUserSession().getAccessToken();
    localStorage.setItem('noauth', 'false');
    localStorage.setItem('idtokenjwt', idToken.getJwtToken());
    localStorage.setItem('accesstokenjwt', accessToken.getJwtToken());
    localStorage.setItem('poolname', appUserPoolName);
    window.location.href = 'index.html?home';
  } catch (reason) {
    console.debug('failed to parse response: ' + reason);
    console.debug('url was: ' + minurl);
    window.location.href = 'index.html';
  }
} else if (curUrl.indexOf('loggedout') >= 0) {
  console.debug('logout complete');
  localStorage.removeItem('noauth');
  localStorage.removeItem('idtokenjwt');
  localStorage.removeItem('cognitoid');
  localStorage.removeItem('username');
  if (noauth === 'true') {
    window.location.href = '/static/indexentry.html';
  } else {
    window.location.href = 'index.html';
  }
} else if (curUrl.indexOf('index.html?dosignout') >= 0) {
  logout();
} else if (curUrl.indexOf('fitbitlogin') >= 0) {
  console.debug('fitbit login is: ' + curUrl);
  const fragmentQueryParameters = {};
  window.location.hash.slice(1).replace(
    new RegExp('([^?=&]+)(=([^&]*))?', 'g'),
    function ($0, $1, $2, $3) { fragmentQueryParameters[$1] = $3; },
  );

  const fitbitAccessToken = fragmentQueryParameters.access_token;
  console.debug('fitbit accesstoken is: ' + fitbitAccessToken);
  const url = 'https://api.fitbit.com/1/user/-/activities/steps/date/today/1m.json';
  fetch(
    url,
    {
      headers: new Headers({
        Authorization: 'Bearer ' + fitbitAccessToken,
      }),
      mode: 'cors',
      method: 'GET',
    },
  ).then(processFitbitResponse)
    .catch(function (error) {
      console.error(error);
    });
} else if (token) {
  window.location.href = 'index.html?home';
} else {
  window.location.href = '/static/indexentry.html';
}

