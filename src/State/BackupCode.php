<?php declare(strict_types=1);

namespace SilverStripe\MFA\State;

use JsonSerializable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\PasswordEncryptor;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;

/**
 * A container for a backup code and its hash, normally used during backup code generation
 */
class BackupCode implements JsonSerializable
{
    use Injectable;

    /**
     * @var string
     */
    protected $code = '';

    /**
     * @var string
     */
    protected $hash = '';

    /**
     * @var string
     */
    protected $algorithm = '';

    /**
     * @var string
     */
    protected $salt = '';

    /**
     * @param string $code
     * @param string $hash
     */
    public function __construct(string $code, string $hash, string $algorithm, string $salt)
    {
        $this->code = $code;
        $this->hash = $hash;
        $this->algorithm = $algorithm;
        $this->salt = $salt;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function getHash(): string
    {
        return $this->hash;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Checks whether the provided code matches a set of provided salt, hash, and algorithm, using the
     * internal PasswordEncryptor API.
     *
     * @return bool
     */
    public function isValid(): bool
    {
        return PasswordEncryptor::create_for_algorithm($this->getAlgorithm())
            ->check($this->getHash(), $this->getCode(), $this->getSalt());
    }

    /**
     * Note: deliberately does not include "code", as this is the data that is stored in DB records
     */
    public function jsonSerialize(): array
    {
        return [
            'hash' => $this->getHash(),
            'algorithm' => $this->getAlgorithm(),
            'salt' => $this->getSalt(),
        ];
    }
}
