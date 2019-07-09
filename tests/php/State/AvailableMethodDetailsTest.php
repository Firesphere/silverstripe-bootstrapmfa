<?php

namespace SilverStripe\MFA\Tests\State;

use PHPUnit_Framework_MockObject_MockObject;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Method\Handler\RegisterHandlerInterface;
use SilverStripe\MFA\Method\MethodInterface;
use SilverStripe\MFA\State\AvailableMethodDetails;

class AvailableMethodDetailsTest extends SapphireTest
{
    /**
     * @var MethodInterface|PHPUnit_Framework_MockObject_MockObject
     */
    protected $method;

    /**
     * @var AvailableMethodDetails
     */
    protected $details;

    protected function setUp()
    {
        parent::setUp();

        $this->method = $this->createMock(MethodInterface::class);
        $this->details = new AvailableMethodDetails($this->method);
    }

    public function testJsonSerialize()
    {
        $this->method->expects($this->once())->method('getName')->willReturn('Backup Codes');
        $result = json_encode($this->details);
        $this->assertContains('Backup Codes', $result);
    }
}
