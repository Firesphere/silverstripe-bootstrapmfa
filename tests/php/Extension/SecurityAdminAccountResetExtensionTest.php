<?php

namespace SilverStripe\MFA\Tests\Extension;

use SilverStripe\Admin\SecurityAdmin;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\MFA\Extension\SecurityAdminAccountResetExtension;
use SilverStripe\Security\Member;
use SilverStripe\Security\SecurityToken;

class SecurityAdminAccountResetExtensionTest extends FunctionalTest
{
    protected static $fixture_file = 'SecurityAdminAccountResetExtensionTest.yml';

    public function setUp()
    {
        parent::setUp();

        SecurityToken::enable();
    }

    public function tearDown()
    {
        parent::tearDown();

        SecurityToken::disable();
    }

    public function testEndpointRequiresCSRF()
    {
        $this->logInAs('admin');

        /** @var Member $member */
        $member = $this->objFromFixture(Member::class, 'squib');

        $response = $this->post(SecurityAdmin::singleton()->Link("reset/{$member->ID}"), [true]);

        $this->assertEquals(400, $response->getStatusCode(), $response->getBody());
        $this->assertContains('Invalid or missing CSRF', $response->getBody());
    }

    public function testResetCanBeInitiatedByAdmin()
    {
        $this->logInAs('admin');

        /** @var Member $member */
        $member = $this->objFromFixture(Member::class, 'squib');

        $response = $this->post(
            SecurityAdmin::singleton()->Link("reset/{$member->ID}"),
            [true],
            null,
            null,
            json_encode(['csrf_token' => SecurityToken::inst()->getValue()])
        );

        $this->assertEquals(200, $response->getStatusCode(), $response->getBody());
        $this->assertEmailSent($member->Email);
    }

    public function testResetCannotBeInitiatedByStandardUser()
    {
        $this->logInAs('squib');

        /** @var Member $member */
        $member = $this->objFromFixture(Member::class, 'admin');

        $response = $this->post(
            SecurityAdmin::singleton()->Link("reset/{$member->ID}"),
            [true],
            null,
            null,
            json_encode(['csrf_token' => SecurityToken::inst()->getValue()])
        );

        $this->assertEquals(403, $response->getStatusCode(), $response->getBody());
        $this->assertContains('Insufficient permissions', $response->getBody());
    }
}
