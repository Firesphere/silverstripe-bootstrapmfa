<?php

namespace Firesphere\BootstrapMFA\Extensions;

use Firesphere\BootstrapMFA\Models\BackupCode;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\Tab;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\DataList;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * Class MemberExtension
 *
 * @package Firesphere\BootstrapMFA
 * @property MemberExtension $owner
 * @property boolean $MFAEnabled
 * @method DataList|BackupCode[] BackupCodes()
 */
class MemberExtension extends DataExtension
{
    use Configurable;

    /**
     * @var array
     */
    private static $db = [
        'MFAEnabled' => 'Boolean(false)',
    ];

    /**
     * @var array
     */
    private static $has_many = [
        'BackupCodes' => BackupCode::class
    ];

    /**
     * @var bool
     */
    protected $updateMFA = false;

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName(['BackupCodes']);
        $session = Controller::curr()->getRequest()->getSession();
        $rootTabSet = $fields->fieldByName("Root");
        $field = LiteralField::create('tokens', $session->get('tokens'));
        $tab = Tab::create(
            'MFA',
            _t(self::class . '.MFATAB', 'Multi Factor Authentication')
        );
        $rootTabSet->push(
            $tab
        );
        $fields->addFieldToTab(
            'Root.MFA',
            $enabled = CheckboxField::create('MFAEnabled', _t(self::class . '.MFAEnabled', 'MFA Enabled'))
        );
        $fields->addFieldToTab(
            'Root.MFA',
            CheckboxField::create('updateMFA', _t(self::class . '.RESETMFA', 'Reset MFA codes'))
        );

        if ($session->get('tokens')) {
            $fields->addFieldToTab('Root.MFA', $field);
            $session->clear('tokens');
        }
    }

    /**
     *
     */
    public function onBeforeWrite()
    {
        if (!$this->owner->MFAEnabled && SiteConfig::current_site_config()->ForceMFA) {
            $this->owner->MFAEnabled = true;
            $this->owner->updateMFA = true;
        }
    }

    /**
     *
     * @throws \Psr\Container\NotFoundExceptionInterface
     */
    public function onAfterWrite()
    {
        parent::onAfterWrite();
        if ($this->owner->updateMFA) {
            $provider = Injector::inst()->get(BootstrapMFAProvider::class);
            $provider->setMember($this->owner);
            $provider->updateTokens();
        }
    }

    public function getBackupcodes()
    {
        return $this->owner->BackupCodes();
    }
}
