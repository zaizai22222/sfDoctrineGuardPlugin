<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 *
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
class BasesfGuardAuthActions extends sfActions
{
  public function executeSignin($request)
  {
    if (isset($_GET['login']) && $_GET['login'] == 'new')
    {
      $user = $this->ssoLogin();
      $this->getUser()->signin($user, true);
      $signinUrl = sfConfig::get('app_sf_guard_plugin_success_signin_url');

      return $this->redirect('' != $signinUrl ? $signinUrl : '@homepage');

    }
    $user = $this->getUser();
    if ($user->isAuthenticated())
    {
      return $this->redirect('@homepage');
    } else {
      $user = $this->ssoLogin();
      $this->getUser()->signin($user, true);
      $signinUrl = sfConfig::get('app_sf_guard_plugin_success_signin_url');

      return $this->redirect('' != $signinUrl ? $signinUrl : '@homepage');
    }
  }

  private function ssoLogin()
  {
    $ssoProvider = new SsoProvider();
    if (!isset($_GET['code'])) {

      // If we don't have an authorization code then get one
      $authUrl = $ssoProvider->getAuthorizationUrl();
      header('Location: '.$authUrl);
      exit;

// Check given state against previously stored one to mitigate CSRF attack
    } else {

      // Try to get an access token (using the authorization code grant)
      $token = $ssoProvider->getAccessToken('authorization_code', [
          'code' => $_GET['code']
      ]);

      // Optional: Now you have a token you can look up a users profile data
      try {
        $userDetails =  $ssoProvider->getUserDetails(new \League\OAuth2\Client\Token\AccessToken(['access_token' => $token->accessToken]));
        $user = Doctrine_Core::getTable('sfGuardUser')->createQuery()
            ->select()
            ->where('username = ?', $userDetails->username)
            ->execute()->getFirst();

        $user->setAccessToken($token->accessToken);
        $user->save();
        return $user;

      } catch (Exception $e) {

        error_log(sprintf('Cannot find user with access token %s', $e->getMessage()));

        throw $e;
      }
    }
  }

  private function ssoLogin()
  {
    $ssoProvider = new SsoProvider();
    if (!isset($_GET['code'])) {

      // If we don't have an authorization code then get one
      $authUrl = $ssoProvider->getAuthorizationUrl();
      header('Location: '.$authUrl);
      exit;

// Check given state against previously stored one to mitigate CSRF attack
    } else {

      // Try to get an access token (using the authorization code grant)
      $token = $ssoProvider->getAccessToken('authorization_code', [
          'code' => $_GET['code']
      ]);

      // Optional: Now you have a token you can look up a users profile data
      try {
        $userDetails =  $ssoProvider->getUserDetails(new \League\OAuth2\Client\Token\AccessToken(['access_token' => $token->accessToken]));
        $user = Doctrine_Core::getTable('sfGuardUser')->createQuery()
            ->select()
            ->where('username = ?', $userDetails->username)
            ->execute()->getFirst();

        $user->setAccessToken($token->accessToken);
        $user->save();
        return $user;

      } catch (Exception $e) {

        error_log(sprintf('Cannot find user with access token %s', $e->getMessage()));

        throw $e;
      }
    }
  }

  public function executeSignout($request)
  {
    $this->getUser()->signOut();

    $signoutUrl = sfConfig::get('app_sf_guard_plugin_success_signout_url', $request->getReferer());

    $this->redirect('' != $signoutUrl ? $signoutUrl : '@homepage');
  }

  public function executeSecure($request)
  {
    $this->getResponse()->setStatusCode(403);
  }

  public function executePassword($request)
  {
    throw new sfException('This method is not yet implemented.');
  }
}
