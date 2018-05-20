<?php

namespace Firesphere\BootstrapMFA\Handlers;

use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginForm;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;

/**
 * Class BootstrapMFALoginHandler
 * @package Firesphere\BootstrapMFA\Handlers
 */
abstract class BootstrapMFALoginHandler extends LoginHandler
{
    /**
     * Key for array to be stored in between steps in the session
     */
    const SESSION_KEY = 'MFALogin';

    /**
     * @var array
     */
    private static $url_handlers = [
        'verify' => 'secondFactor'
    ];

    /**
     * @var array
     */
    private static $allowed_actions = [
        'LoginForm',
        'dologin',
        'secondFactor',
        'MFAForm'
    ];

    /**
     * Return the MemberLoginForm form
     */
    public function LoginForm()
    {
        return BootstrapMFALoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }

    /**
     * @param array $data
     * @param LoginForm $form
     * @param HTTPRequest $request
     * @param $validationResult
     * @return ValidationResult|Member
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    public function validate($data, $form, $request, &$validationResult)
    {
        if (!$validationResult) {
            $validationResult = new ValidationResult();
        }
        /** @var BootstrapMFAProvider $provider */
        $provider = new BootstrapMFAProvider();
        $memberID = $request->getSession()->get(static::SESSION_KEY . '.MemberID');
        /** @var Member $member */
        $member = Member::get()->byID($memberID);
        $provider->setMember($member);
        $member = $provider->verifyToken($data['token'], $validationResult);
        if ($member instanceof Member && $validationResult->isValid()) {
            return $member;
        }

        return $validationResult;
    }

    /**
     * @param array $data
     * @param MemberLoginForm $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function doLogin($data, MemberLoginForm $form, HTTPRequest $request)
    {
        $session = $request->getSession();
        /** @var Member $member */
        $member = $this->checkLogin($data, $request, $message);
        if ($message->isValid()) {
            $session->set(static::SESSION_KEY . '.MemberID', $member->ID);
            $session->set(static::SESSION_KEY . '.Data', $data);
            if (!empty($data['BackURL'])) {
                $session->set(static::SESSION_KEY . '.BackURL', $data['BackURL']);
            }

            return $this->redirect($this->link('verify'));
        }

        return $this->redirectBack();
    }

    /**
     * @return array
     */
    public function secondFactor()
    {
        return ['Form' => $this->MFAForm()];
    }

    /**
     * @return mixed
     */
    abstract public function MFAForm();
}
