<?php

namespace dokuwiki\plugin\oauthazure;

use dokuwiki\HTTP\DokuHTTPClient;
use dokuwiki\plugin\oauth\Service\AbstractOAuth2Base;
use OAuth\Common\Http\Uri\Uri;

/**
 * Custom Service for Azure oAuth
 */
class Azure extends AbstractOAuth2Base
{
    /**
     * Defined scopes are listed here:
     * @link https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent
     */
    const SCOPE_OPENID = 'openid';
    const SCOPE_EMAIL = 'email';
    const SCOPE_PROFILE = 'profile';
    const SCOPE_OFFLINE = 'offline_access';
    const SCOPE_USERREAD = 'https://graph.microsoft.com/user.read';
    const SCOPE_GROUPMEMBER = 'https://graph.microsoft.com/GroupMember.Read.All';

    /**
     * Endpoints are listed here:
     * @link https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#authorization-server-metadata
     */
    const ENDPOINT_AUTH = 'authorization_endpoint';
    const ENDPOINT_TOKEN = 'token_endpoint';
    const ENDPOINT_USERINFO = 'userinfo_endpoint';
    const ENDPOINT_LOGOUT = 'end_session_endpoint';

    // graph API endpoint to read group memberships
    const GRAPH_MEMBEROF = 'https://graph.microsoft.com/v1.0/me/memberof';

    /** @var string[] discovery URL cache */
    protected $discovery;

    /**
     * Return URI of discovered endpoint
     *
     * @return string
     */
    public function getEndpoint(string $endpoint)
    {
        if (!isset($this->discovery)) {
            $plugin = plugin_load('action', 'oauthazure');
            $discover = 'https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration';
            $discover = sprintf($discover, $plugin->getConf('tenant'));

            $http = new DokuHTTPClient();
            $json = $http->get($discover);
            if (!$json) return '';
            $this->discovery = json_decode($json, true);
        }
        if (!isset($this->discovery[$endpoint])) return '';
        return $this->discovery[$endpoint];
    }

    /** @inheritdoc */
    public function getAuthorizationEndpoint()
    {
        global $conf;
        $uri = new Uri($this->getEndpoint(self::ENDPOINT_AUTH));
        if (isset($conf['plugin']['oauth']['mailRestriction'])) {
            $uri->addToQuery('domain_hint', substr($conf['plugin']['oauth']['mailRestriction'], 1));
        }
        return $uri;
    }

    /** @inheritdoc */
    public function getAccessTokenEndpoint()
    {
        $uri = new Uri($this->getEndpoint(self::ENDPOINT_TOKEN));
        //$uri->addToQuery('requested_token_use', 'on_behalf_of');
        return $uri;
    }

    /** @inheritdoc */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * Logout from Azure
     *
     * @return void
     * @throws \OAuth\Common\Exception\Exception
     */
    public function logout()
    {
        send_redirect($this->getEndpoint(self::ENDPOINT_LOGOUT));
    }
}
