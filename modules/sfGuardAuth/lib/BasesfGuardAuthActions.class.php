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
  const ACCESS_TOKEN_DURATION = 86400;

  public function executeSignin($request)
  {
    $user = $this->getUser();
    if ($user->isAuthenticated()) {
      return $this->redirect('@homepage');
    }

    if (sfConfig::get('app_features_sso')) {
      $user = $this->ssoLogin();
      $this->getUser()->signin($user, true);
      $signinUrl = sfConfig::get('app_sf_guard_plugin_success_signin_url');

      return $this->redirect('' != $signinUrl ? $signinUrl : '@homepage');
    }

    $redirectUrl = $this->formLogin($request);

    return $this->redirect($redirectUrl);
  }

  public function executeSignout($request)
  {
    $accessToken = $this->getUser()->getGuardUser()->getAccessToken();
    $this->getUser()->signOut();

    $ssoProvider = new SsoProvider();

    try {
      $ssoProvider->logoutUser($accessToken);
    } catch (\Exception $e) {
      if (sfConfig::get('sf_logging_enabled'))
      {
        sfContext::getInstance()->getLogger()->error($e->getMessage());
      }
    }

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

  private function formLogin($request)
  {
     $class = sfConfig::get('app_sf_guard_plugin_signin_form', 'sfGuardFormSignin');
     $this->form = new $class();

     if ($request->isMethod('post')) {
       $this->form->bind($request->getParameter('signin'));
       if ($this->form->isValid()) {
         $values = $this->form->getValues();
         $this->getUser()->signin($values['user'], array_key_exists('remember', $values) ? $values['remember'] : false);

         // always redirect to a URL set in app.yml
         // or to the referer
         // or to the homepage
         $signinUrl = sfConfig::get('app_sf_guard_plugin_success_signin_url', $user->getReferer($request->getReferer()));

         return $this->redirect('' != $signinUrl ? $signinUrl : '@homepage');
       }
     }
     else {
       if ($request->isXmlHttpRequest()) {
         $this->getResponse()->setHeaderOnly(true);
         $this->getResponse()->setStatusCode(401);

         return sfView::NONE;
       }

       // if we have been forwarded, then the referer is the current URL
       // if not, this is the referer of the current request
       $user->setReferer($this->getContext()->getActionStack()->getSize() > 1 ? $request->getUri() : $request->getReferer());

       $module = sfConfig::get('sf_login_module');
       if ($this->getModuleName() != $module) {
         return $this->redirect($module.'/'.sfConfig::get('sf_login_action'));
       }

       $this->getResponse()->setStatusCode(401);
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


        $currentDate = new \DateTime();
        $expirationDate = clone $currentDate;
        $expirationDate->add(new \DateInterval('PT'.self::ACCESS_TOKEN_DURATION.'S'));

        $user->setAccessToken($token->accessToken);
        $user->setAccessTokenExpirationDate($expirationDate->format('Y-m-d H:i:s'));
        $user->save();
        return $user;

      } catch (Exception $e) {

        error_log(sprintf('Cannot find user with access token %s', $e->getMessage()));

        throw $e;
      }
    }
  }

}
