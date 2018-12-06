<?php
/**
 * This file is part of workerman.
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @author    walkor<walkor@workerman.net>
 * @copyright walkor<walkor@workerman.net>
 * @link      http://www.workerman.net/
 * @license   http://www.opensource.org/licenses/mit-license.php MIT License
 */
namespace Workerman\Protocols;

use Workerman\Connection\TcpConnection;

/**
 * JsonZero Protocol.
 */
class Jsontext
{
    /**
     * Check the integrity of the package.
     *
     * @param string        $buffer
     * @param TcpConnection $connection
     * @return int
     */
    public static function input($buffer, TcpConnection $connection)
    {
        // Judge whether the package length exceeds the limit.
        if (strlen($buffer) >= TcpConnection::$maxPackageSize) {
            $connection->close();
            return 0;
        }
        //  Find the position of  "\n".
        $pos = strpos($buffer, "\n");
        //  Find the position of  "\0".
        if ($pos === false ) {
            $pos = strpos($buffer, "\0");
        }
        // No "\n", packet length is unknown, continue to wait for the data so return 0.
        if ($pos === false ) {
            return 0;
        }
        // Return the current package length.
        return $pos + 1;
    }

    /**
     * Encode.
     *
     * @param string $buffer
     * @return string
     */
    public static function encode($buffer)
    {
        // Add "\n"
		return json_encode($buffer,JSON_UNESCAPED_UNICODE) . "\n";
    }

    /**
     * Decode.
     *
     * @param string $buffer
     * @return string
     */
    public static function decode($buffer)
    {
        // Remove "\n" and decode
        return json_decode(trim($buffer));
    }
}
