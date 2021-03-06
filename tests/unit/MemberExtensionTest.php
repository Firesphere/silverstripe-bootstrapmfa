<?php

namespace Firesphere\BootstrapMFA\Tests;

use Firesphere\BootstrapMFA\Extensions\MemberExtension;
use Firesphere\BootstrapMFA\Extensions\SiteConfigExtension;
use Firesphere\BootstrapMFA\Models\BackupCode;
use Firesphere\BootstrapMFA\Tests\Helpers\CodeHelper;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\TabSet;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\SiteConfig\SiteConfig;

class MemberExtensionTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/member.yml';

    public function testMemberCodesExpired()
    {
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'member1');

        Security::setCurrentUser($member);
        $member->updateMFA = true;
        $member->write();

        /** @var DataList|BackupCode $codes */
        $codes = $member->BackupCodes()->column('ID');

        $member->updateMFA = true;
        $member->write();

        foreach ($codes as $code) {
            /** @var BackupCode $backup */
            $backup = BackupCode::get()->byID($code);
            $this->assertNull($backup);
        }
    }

    public function testMemberCodesNotExpired()
    {
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'member1');

        Security::setCurrentUser($member);
        $member->updateMFA = true;
        $member->write();

        /** @var DataList|BackupCode $codes */
        $codes = $member->BackupCodes()->column('ID');

        $member->updateMFA = false;
        $member->write();

        foreach ($codes as $code) {
            /** @var BackupCode $backup */
            $backup = BackupCode::get()->byID($code);
            $this->assertNotNull($backup);
        }
    }

    public function testUpdateCMSFields()
    {
        $fields = FieldList::create([TabSet::create('Root')]);

        /** @var MemberExtension $extension */
        $extension = Injector::inst()->get(MemberExtension::class);

        // Something something in session
        Controller::curr()->getRequest()->getSession()->set('tokens', '123456');
        $extension->updateCMSFields($fields);

        $this->assertNull(Controller::curr()->getRequest()->getSession()->get('tokens'));
    }

    public function testUpdateCMSFieldsNoTokens()
    {
        $fields = FieldList::create([TabSet::create('Root')]);

        $extension = Injector::inst()->get(MemberExtension::class);

        $extension->updateCMSFields($fields);

        $this->assertFalse($fields->hasField('BackupTokens'));
    }

    public function testOnAfterWrite()
    {
        /** @var MemberExtension $extension */
        $extension = Injector::inst()->get(MemberExtension::class);
        /** @var Member $member */
        $member = $this->objFromFixture(Member::class, 'member1');
        $member->updateMFA = true;

        Security::setCurrentUser($member);
        $extension->setOwner($member);

        $extension->onAfterWrite();

        $this->assertCount(15, CodeHelper::getCodesFromSession());
        $this->assertCount(15, $member->BackupCodes());
    }

    public function testOnBeforeWrite()
    {
        /** @var MemberExtension $extension */
        $extension = Injector::inst()->get(MemberExtension::class);
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'member1');
        Security::setCurrentUser($member);
        $member->MFAEnabled = false;
        $member->write();
        $config = SiteConfig::current_site_config();
        $config->ForceMFA = DBDatetime::now()->Format(DBDatetime::ISO_DATE);
        $config->write;
        $extension->setOwner($member);

        $extension->onBeforeWrite();

        $this->assertTrue($member->MFAEnabled);

        /** @var MemberExtension $extension */
        $member->MFAEnabled = false;
        $config->ForceMFA = null;
        $config->write;

        $extension->onBeforeWrite();

        $this->assertFalse($member->MFAEnabled);
    }

    public function testIsInGracePeriod()
    {
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'member2');
        Security::setCurrentUser($member);
        $this->assertTrue($member->isInGracePeriod());
        /** @var SiteConfig|SiteConfigExtension $config */
        $config = SiteConfig::current_site_config();
        $config->ForceMFA = DBDatetime::now()->Format(DBDatetime::ISO_DATE);
        $config->write();
        $this->assertTrue($member->isInGracePeriod());
        $member->Created = '1970-01-01 00:00:00';
        $member->write();
        $this->assertFalse($member->isInGracePeriod());
        $member->Created = DBDatetime::now()->Format(DBDatetime::ISO_DATETIME);
        $member->MFAEnabled = true;
        $member->write();
        $this->assertFalse($member->isInGracePeriod());
    }
}
