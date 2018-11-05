<?php

namespace Firesphere\BootstrapMFA\Forms;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;

/**
 * Class BootstrapMFALoginForm
 * @package Firesphere\BootstrapMFA\Forms
 */
class BootstrapMFALoginForm extends MemberLoginForm
{
    /**
     * @return FieldList
     */
    public function getFormFields()
    {
        $fields = parent::getFormFields();
        $session = $this->controller->getRequest()->getSession();
        if ($session->get('tokens')) {
            $field = LiteralField::create('tokens', $session->get('tokens'));
            $fields->push($field);
            $session->clear('tokens');
        }

        return $fields;
    }

    public function getAuthenticatorName()
    {
        return _t(__CLASS__ . '.AuthenticatorName', 'E-mail & Password (with MFA)');
    }
}
