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

/**
 * Rltlv Protocol.
 */

class Rltlv
{
    /**
     * Check the integrity of the package.
     *
     * @param string        $buffer
     * @param $connection
     * @return int
     */
    public static function input($buffer, $connection)
    {
        if (strlen($buffer) < 16) {
            return 0;
        }
        $unpack_data = unpack('S1length', substr($buffer,14,2));
        return $unpack_data['length'] + 12;
    }
	
	public static function unpackFormat($requestType){
		$fields = rltlv_fields($requestType);
		if(!$fields)
			return null;
		$format = '';
		foreach($fields as $field){
			list($name,$type,$num) = $field;
			switch($type){
			case 'double':
				$format .= 'd1' . $name . '/';
				break;
			case 'float':
				$format .= 'f1' . $name . '/';
				break;
			case 'short':
				$format .= 'S1' . $name . '/';
				break;
			case 'integer':
				$format .= 'L1' . $name . '/';
				break;
			case 'char':
				$format .= 'a' . $num . $name . '/';
				break;
			case 'string':
				$format .= 'a' . $num . $name . '/';
				break;
			}
		}
		return trim($format,'/');
	}
	
	public static function packValue($value){
		//获取字段定义
		$fields = rltlv_fields($value['type']);
		if(!$fields)
			return '';
		//生成编码格式
		$format = '';
		foreach($fields as $field){
			list($name,$type,$num) = $field;
			switch($type){
			case 'double':
				$format .= 'd1';
				break;
			case 'float':
				$format .= 'f1';
				break;
			case 'short':
				$format .= 'S1';
				break;
			case 'integer':
				$format .= 'L1';
				break;
			case 'char':
				$format .= 'C' . $num ;
				break;
			case 'string':
				$format .= 'C' . $num ;
				break;
			}
		}
		//二进制编码
		$params = array();
		array_push($params,$format);
		foreach($fields as $field){
			list($name,$type) = $field;
			array_push($params,$value[$name]);
		}
		return call_user_func_array('pack',$params);
	}
	

    /**
     * Decode.
     *
     * @param string $buffer
     * @return string
     */
    public static function decode($buffer)
    {
		//解码头部数据
        $unpack_head = unpack('C2magic/C1version/C1crc/S1session/C6sn/S1type/S1length', $buffer);
		$unpack_head['method'] = sprintf("method%'04x",$unpack_head['type']);
		//判断前2位引导符
		if( $unpack_head['magic1'] != 0x52|| $unpack_head['magic2'] !=  0x4C )
			return null;
		//组合出sn
		$unpack_head['sn'] = chr($unpack_head['sn1']) . chr($unpack_head['sn2']) . chr($unpack_head['sn3']) . chr($unpack_head['sn4']) . chr($unpack_head['sn5']) . chr($unpack_head['sn6']);
		unset($unpack_head['sn1']);
		unset($unpack_head['sn2']);
		unset($unpack_head['sn3']);
		unset($unpack_head['sn4']);
		unset($unpack_head['sn5']);
		unset($unpack_head['sn6']);
		//如果长度等于4则没有tlv中v
		if($unpack_head['length'] == 4)
			return $unpack_head;
		//解码值数据
		$format = self::unpackFormat($unpack_head['type']);
		if(!$format)
			return null;
		
		$unpack_value = unpack($format, substr($buffer,16));
		//头部+值一起返回
		return array_merge($unpack_head,$unpack_value);
    }

    /**
     * Encode.
     *
     * @param string $buffer
     * @return string
     */
    public static function encode($buffer)
    {
		$pack_value = self::packValue($buffer);
        $length = 4 + strlen($pack_value);
        return pack('C1C1C1C1S1', 0x52,0x4C,0x01,0x00,$buffer['session']) . $buffer['sn'] . pack('S1S1',$buffer['type'],$length) . $pack_value;
    }
}
