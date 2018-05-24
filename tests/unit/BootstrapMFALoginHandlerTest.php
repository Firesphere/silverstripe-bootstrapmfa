<?php

namespace Firesphere\BootstrapMFA\Tests;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use Firesphere\BootstrapMFA\Models\BackupCode;
use Firesphere\BootstrapMFA\Tests\Helpers\CodeHelper;
use Firesphere\BootstrapMFA\Tests\Mock\MockBootstrapMFAHandler;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class BootstrapMFALoginHandlerTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/member.yml';

    /**
     * @var HTTPRequest
     */
    protected $request;

    /**
     * @var Member
     */
    protected $member;

    /**
     * @var BootstrapMFAAuthenticator
     */
    protected $authenticator;

    /**
     * @var BootstrapMFALoginForm
     */
    protected $form;

    /**
     * @var MockBootstrapMFAHandler
     */
    protected $handler;

    public function testLoginForm()
    {
        $form = $this->handler->LoginForm();

        $this->assertInstanceOf(BootstrapMFALoginForm::class, $form);
    }

    public function testSuccessValidate()
    {
        Security::setCurrentUser($this->member);
        BackupCode::generateTokensForMember($this->member);
        $tokens = CodeHelper::getCodesFromSession();
        $data = ['token' => $tokens[0]];
        $response = $this->handler->validate($data, $this->form, $this->request, $result);

        $this->assertInstanceOf(Member::class, $response);
    }

    public function testErrorValidate()
    {
        $data = ['token' => 'wrongtokenforsure'];
        $this->handler->validate($data, $this->form, $this->request, $result);

        $this->assertFalse($result->isValid());
    }

    public function testDoLogin()
    {
        $data = [
            'Email'    => 'test@test.com',
            'Password' => 'password1'
        ];

        $response = $this->handler->doLogin($data, $this->form, $this->request);

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertContains('verify', $response->getHeader('location'));

        $session = $this->request->getSession();
        $expected = [
            'MemberID' => 1,
            'Data'     =>
                [
                    'Email'    => 'test@test.com',
                    'Password' => 'password1',
                ]
        ];
        $this->assertEquals($expected, $session->get(BootstrapMFAAuthenticator::SESSION_KEY));
    }

    public function testBackURLLogin()
    {
        $data = [
            'Email'    => 'test@test.com',
            'Password' => 'password1',
            'BackURL'  => '/memberlocation'
        ];

        $response = $this->handler->doLogin($data, $this->form, $this->request);

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertContains('verify', $response->getHeader('location'));

        $session = $this->request->getSession();
        $expected = [
            'MemberID' => 1,
            'BackURL'  => '/memberlocation',
            'Data'     =>
                [
                    'Email'    => 'test@test.com',
                    'Password' => 'password1',
                    'BackURL'  => '/memberlocation',
                ],
        ];
        $this->assertEquals($expected, $session->get(BootstrapMFAAuthenticator::SESSION_KEY));
    }

    public function testDoWrongLogin()
    {
        $data = [
            'Email'    => 'test@test.com',
            'Password' => 'wrongpassword'
        ];

        $response = $this->handler->doLogin($data, $this->form, $this->request);

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertContains('login', $response->getHeader('location'));
    }

    public function testMFALoginForm()
    {
        $result = $this->handler->secondFactor();

        $this->assertArrayHasKey('Form', $result);
    }

    protected function setUp()
    {
        parent::setUp();
        $this->request = Controller::curr()->getRequest();
        $this->member = $this->objFromFixture(Member::class, 'member1');

        $session = $this->request->getSession();
        $session->set(BootstrapMFAAuthenticator::SESSION_KEY . '.MemberID', $this->member->ID);

        $this->authenticator = Injector::inst()->create(BootstrapMFAAuthenticator::class);
        $this->form = Injector::inst()->createWithArgs(
            BootstrapMFALoginForm::class,
            [Controller::curr(), $this->authenticator, 'test']
        );
        $this->handler = Injector::inst()->createWithArgs(
            MockBootstrapMFAHandler::class,
            ['login', $this->authenticator]
        );
    }
}
