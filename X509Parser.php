<?php
/**
 * This file was developed by Nathan <nathan@webr3.org>
 *
 * Created:     nathan - 7 May 2010 04:14:15
 * Modified:    SVN: $Id$
 * PHP Version: 5.1.6+
 *
 * @package   @project.name@
 * @author    Nathan <nathan@webr3.org>
 * @version   SVN: $Revision$
 */

define( 'ASN1_TYPE_UNIVERSAL' , 0 );
define( 'ASN1_TYPE_APPLICATION' , 64 );
define( 'ASN1_TYPE_CONTEXT_SPECIFIC' , 128 );
define( 'ASN1_TYPE_PRIVATE' , 192 );

define( 'ASN1_PRIMITIVE' , 0 );
define( 'ASN1_CONSTRUCTED' , 32 );

define( 'ASN1_DEBUG' , true );

/**
 * X509 Decoder
 * 
 * @package   @project.name@
 * @author    Nathan <nathan@webr3.org>
 * @version   SVN: $Revision$
 */
class X509Decoder
{
	private static $_OIDS = array(
		'0.2.262.1.10.0' => 'extension',
		'0.2.262.1.10.1.1' => 'signature',
		'1.2.840.113549.1.1' => 'pkcs-1',
		'1.2.840.113549.1.1.1' => 'rsaEncryption',
		'1.2.840.113549.1.1.4' => 'md5withRSAEncryption',
		'1.2.840.113549.1.1.5' => 'sha1withRSAEncryption',
		'1.2.840.113549.1.1.6' => 'rsaOAEPEncryptionSET',
		'1.2.840.113549.1.7' => 'pkcs-7',
		'1.2.840.113549.1.7.1' => 'data',
		'1.2.840.113549.1.7.2' => 'signedData',
		'1.2.840.113549.1.7.3' => 'envelopedData',
		'1.2.840.113549.1.7.4' => 'signedAndEnvelopedData',
		'1.2.840.113549.1.7.5' => 'digestedData',
		'1.2.840.113549.1.7.6' => 'encryptedData',
		'1.2.840.113549.1.7.7' => 'dataWithAttributes',
		'1.2.840.113549.1.7.8' => 'encryptedPrivateKeyInfo',
		'1.2.840.113549.1.9.22.1' => 'x509Certificate(for.PKCS.#12)',
		'1.2.840.113549.1.9.23.1' => 'x509Crl(for.PKCS.#12)',
		'1.2.840.113549.1.9.1' => 'emailAddress',
		'1.2.840.113549.1.9.3' => 'contentType',
		'1.2.840.113549.1.9.4' => 'messageDigest',
		'1.2.840.113549.1.9.5' => 'signingTime',
		'2.16.840.1.113730.1' => 'cert-extension',
		'2.16.840.1.113730.1.1' => 'netscape-cert-type',
		'2.16.840.1.113730.1.12' => 'netscape-ssl-server-name',
		'2.16.840.1.113730.1.13' => 'netscape-comment',
		'2.16.840.1.113730.1.2' => 'netscape-base-url',
		'2.16.840.1.113730.1.3' => 'netscape-revocation-url',
		'2.16.840.1.113730.1.4' => 'netscape-ca-revocation-url',
		'2.16.840.1.113730.1.7' => 'netscape-cert-renewal-url',
		'2.16.840.1.113730.1.8' => 'netscape-ca-policy-url',
		'2.23.42.0' => 'contentType',
		'2.23.42.1' => 'msgExt',
		'2.23.42.10' => 'national',
		'2.23.42.2' => 'field',
		'2.23.42.2.0' => 'fullName',
		'2.23.42.2.1' => 'givenName',
		'2.23.42.2.10' => 'amount',
		'2.23.42.2.2' => 'familyName',
		'2.23.42.2.3' => 'birthFamilyName',
		'2.23.42.2.4' => 'placeName',
		'2.23.42.2.5' => 'identificationNumber',
		'2.23.42.2.6' => 'month',
		'2.23.42.2.7' => 'date',
		'2.23.42.2.7.11' => 'accountNumber',
		'2.23.42.2.7.12' => 'passPhrase',
		'2.23.42.2.8' => 'address',
		'2.23.42.3' => 'attribute',
		'2.23.42.3.0' => 'cert',
		'2.23.42.3.0.0' => 'rootKeyThumb',
		'2.23.42.3.0.1' => 'additionalPolicy',
		'2.23.42.4' => 'algorithm',
		'2.23.42.5' => 'policy',
		'2.23.42.5.0' => 'root',
		'2.23.42.6' => 'module',
		'2.23.42.7' => 'certExt',
		'2.23.42.7.0' => 'hashedRootKey',
		'2.23.42.7.1' => 'certificateType',
		'2.23.42.7.2' => 'merchantData',
		'2.23.42.7.3' => 'cardCertRequired',
		'2.23.42.7.5' => 'setExtensions',
		'2.23.42.7.6' => 'setQualifier',
		'2.23.42.8' => 'brand',
		'2.23.42.9' => 'vendor',
		'2.23.42.9.22' => 'eLab',
		'2.23.42.9.31' => 'espace-net',
		'2.23.42.9.37' => 'e-COMM',
		'2.5.29.1' => 'authorityKeyIdentifier',
		'2.5.29.10' => 'basicConstraints',
		'2.5.29.11' => 'nameConstraints',
		'2.5.29.12' => 'policyConstraints',
		'2.5.29.13' => 'basicConstraints',
		'2.5.29.14' => 'subjectKeyIdentifier',
		'2.5.29.15' => 'keyUsage',
		'2.5.29.16' => 'privateKeyUsagePeriod',
		'2.5.29.17' => 'subjectAltName',
		'2.5.29.18' => 'issuerAltName',
		'2.5.29.19' => 'basicConstraints',
		'2.5.29.2' => 'keyAttributes',
		'2.5.29.20' => 'cRLNumber',
		'2.5.29.21' => 'cRLReason',
		'2.5.29.22' => 'expirationDate',
		'2.5.29.23' => 'instructionCode',
		'2.5.29.24' => 'invalidityDate',
		'2.5.29.25' => 'cRLDistributionPoints',
		'2.5.29.26' => 'issuingDistributionPoint',
		'2.5.29.27' => 'deltaCRLIndicator',
		'2.5.29.28' => 'issuingDistributionPoint',
		'2.5.29.29' => 'certificateIssuer',
		'2.5.29.3' => 'certificatePolicies',
		'2.5.29.30' => 'nameConstraints',
		'2.5.29.31' => 'cRLDistributionPoints',
		'2.5.29.32' => 'certificatePolicies',
		'2.5.29.33' => 'policyMappings',
		'2.5.29.34' => 'policyConstraints',
		'2.5.29.35' => 'authorityKeyIdentifier',
		'2.5.29.36' => 'policyConstraints',
		'2.5.29.37' => 'extKeyUsage',
		'2.5.29.4' => 'keyUsageRestriction',
		'2.5.29.5' => 'policyMapping',
		'2.5.29.6' => 'subtreesConstraint',
		'2.5.29.7' => 'subjectAltName',
		'2.5.29.8' => 'issuerAltName',
		'2.5.29.9' => 'subjectDirectoryAttributes',
		'2.5.4.0' => 'objectClass',
		'2.5.4.1' => 'aliasedEntryName',
		'2.5.4.10' => 'organizationName',
		'2.5.4.10.1' => 'collectiveOrganizationName',
		'2.5.4.11' => 'organizationalUnitName',
		'2.5.4.11.1' => 'collectiveOrganizationalUnitName',
		'2.5.4.12' => 'title',
		'2.5.4.13' => 'description',
		'2.5.4.14' => 'searchGuide',
		'2.5.4.15' => 'businessCategory',
		'2.5.4.16' => 'postalAddress',
		'2.5.4.16.1' => 'collectivePostalAddress',
		'2.5.4.17' => 'postalCode',
		'2.5.4.17.1' => 'collectivePostalCode',
		'2.5.4.18' => 'postOfficeBox',
		'2.5.4.18.1' => 'collectivePostOfficeBox',
		'2.5.4.19' => 'physicalDeliveryOfficeName',
		'2.5.4.19.1' => 'collectivePhysicalDeliveryOfficeName',
		'2.5.4.2' => 'knowledgeInformation',
		'2.5.4.20' => 'telephoneNumber',
		'2.5.4.20.1' => 'collectiveTelephoneNumber',
		'2.5.4.21' => 'telexNumber',
		'2.5.4.21.1' => 'collectiveTelexNumber',
		'2.5.4.22.1' => 'collectiveTeletexTerminalIdentifier',
		'2.5.4.23' => 'facsimileTelephoneNumber',
		'2.5.4.23.1' => 'collectiveFacsimileTelephoneNumber',
		'2.5.4.25' => 'internationalISDNNumber',
		'2.5.4.25.1' => 'collectiveInternationalISDNNumber',
		'2.5.4.26' => 'registeredAddress',
		'2.5.4.27' => 'destinationIndicator',
		'2.5.4.28' => 'preferredDeliveryMehtod',
		'2.5.4.29' => 'presentationAddress',
		'2.5.4.3' => 'commonName',
		'2.5.4.31' => 'member',
		'2.5.4.32' => 'owner',
		'2.5.4.33' => 'roleOccupant',
		'2.5.4.34' => 'seeAlso',
		'2.5.4.35' => 'userPassword',
		'2.5.4.36' => 'userCertificate',
		'2.5.4.37' => 'caCertificate',
		'2.5.4.38' => 'authorityRevocationList',
		'2.5.4.39' => 'certificateRevocationList',
		'2.5.4.4' => 'surname',
		'2.5.4.40' => 'crossCertificatePair',
		'2.5.4.41' => 'name',
		'2.5.4.42' => 'givenName',
		'2.5.4.43' => 'initials',
		'2.5.4.44' => 'generationQualifier',
		'2.5.4.45' => 'uniqueIdentifier',
		'2.5.4.46' => 'dnQualifier',
		'2.5.4.47' => 'enhancedSearchGuide',
		'2.5.4.48' => 'protocolInformation',
		'2.5.4.49' => 'distinguishedName',
		'2.5.4.5' => 'serialNumber',
		'2.5.4.50' => 'uniqueMember',
		'2.5.4.51' => 'houseIdentifier',
		'2.5.4.52' => 'supportedAlgorithms',
		'2.5.4.53' => 'deltaRevocationList',
		'2.5.4.55' => 'clearance',
		'2.5.4.58' => 'crossCertificatePair',
		'2.5.4.6' => 'countryName',
		'2.5.4.7' => 'localityName',
		'2.5.4.7.1' => 'collectiveLocalityName',
		'2.5.4.8' => 'stateOrProvinceName',
		'2.5.4.8.1' => 'collectiveStateOrProvinceName',
		'2.5.4.9' => 'streetAddress',
		'2.5.4.9.1' => 'collectiveStreetAddress',
		'2.5.6.0' => 'top',
		'2.5.6.1' => 'alias',
		'2.5.6.10' => 'residentialPerson',
		'2.5.6.11' => 'applicationProcess',
		'2.5.6.12' => 'applicationEntity',
		'2.5.6.13' => 'dSA',
		'2.5.6.14' => 'device',
		'2.5.6.15' => 'strongAuthenticationUser',
		'2.5.6.16' => 'certificateAuthority',
		'2.5.6.17' => 'groupOfUniqueNames',
		'2.5.6.2' => 'country',
		'2.5.6.21' => 'pkiUser',
		'2.5.6.22' => 'pkiCA',
		'2.5.6.3' => 'locality',
		'2.5.6.4' => 'organization',
		'2.5.6.5' => 'organizationalUnit',
		'2.5.6.6' => 'person',
		'2.5.6.7' => 'organizationalPerson',
		'2.5.6.8' => 'organizationalRole',
		'2.5.6.9' => 'groupOfNames',
		'2.5.8' => 'X.500-Algorithms',
		'2.5.8.1' => 'X.500-Alg-Encryption',
		'2.5.8.1.1' => 'rsa',
		'2.54.1775.2' => 'hashedRootKey',
		'2.54.1775.3' => 'certificateType',
		'2.54.1775.4' => 'merchantData',
		'2.54.1775.5' => 'cardCertRequired',
		'2.54.1775.7' => 'setQualifier',
		'2.54.1775.99' => 'set-data',
	);
	
	private static $_DECODE = array(
		'subjectAltName'
	);
	
	private $unpacked;
	private $decoded;
	
	public function __construct()
	{
		$this->unpacked = array();
		$this->decoded = array();
	}
	
	public function decode( $x509 )
	{
		if( strpos($x509 , 'BEGIN CERTIFICATE') ) {
			// PEM Encoded
			$x509 = str_replace( "-----BEGIN CERTIFICATE-----" , '' , $x509 );
			$x509 = trim( str_replace( "\n-----END CERTIFICATE-----" , '' , $x509 ) );
		}
		if( $unpacked = base64_decode( $x509 , false ) ) {
			$unpacked = str_split( $unpacked , 1 );
			foreach( $unpacked as $index => $dec ) {
				$unpacked[$index] = dechex( ord($dec) );
			}
			$this->unpacked = $unpacked;
			$this->decoded = $this->parse();
			return $this->getDecoded();
		}
		throw new InvalidArgumentException( 'X.509 Certificate must be PEM or DER encoded!' );		
	}
	
	private function getDecoded()
	{
		$d = $this->decoded;
		$cert = array(
			'data' => array(
				'version' => $d[0][0],
				'serial-number' => $d[0][1],
				'algorithm' => $d[0][2][0],
				'issuer' => $d[0][3][0],
				'validity' => $d[0][4],
				'subject' => $d[0][5][0],
				'public-key' => array(
					'algorithm' => $d[0][6][0][0],
					'rsa-public-key' => $d[0][6][1],
					),
				),
			'signature' => array(
				'algorithm' => $d[1][0],
				'signature' => $d[2],
				),
		);
		
		$this->unpacked = explode(' ' , $cert['data']['public-key']['rsa-public-key'] );
		$pkey = $this->parse();
		$cert['data']['public-key']['rsa-public-key'] = array(
			'modulus' => $pkey[0],
			'exponent' => $pkey[1],
		);
		print_r($d);
		if( isset($d[0][7]) && !count($d[0][7]) ) {
			unset($d[0][7]);
		}
		if( isset($d[0][7]) && count($d[0][7]) ) {
			if( count($d[0][7]) == 1 && count($d[0][7][0]) > 1 ) {
				$d[0][7] = $d[0][7][0];
			}
			$extensions = array();
			foreach( $d[0][7] as $index => $extension ) {
				$key = array_shift($extension);
				if( in_array( $key , self::$_DECODE ) ) {
					$this->unpacked = explode(' ' , $extension[0] );
					$extension = $this->parse( true );
				}
				$extensions[ $key ] = $extension;
			}
			$cert['data']['extensions'] = $extensions;
		}
		print_r( $cert );
		return $cert;
	}
	
	private function getBit( $dec=TRUE )
	{
		$bit = array_shift($this->unpacked);
		return $dec ? hexdec($bit) : $bit;
	}
	
	private function parse( $trace=false )
	{
		
		$identifier = $this->getBit( FALSE );
		if( $identifier == 0 ) {
			$identifier = $this->getBit( FALSE );
		}
		$checker = hexdec($identifier);
		
		$type = ASN1_TYPE_UNIVERSAL;
		$constructed = FALSE;
		
		if( $checker >= ASN1_TYPE_PRIVATE ) {
			$type = ASN1_TYPE_PRIVATE;
		} elseif( $checker >= ASN1_TYPE_CONTEXT_SPECIFIC ) {
			$type = ASN1_TYPE_CONTEXT_SPECIFIC;
		} elseif( $checker >= ASN1_TYPE_APPLICATION ) {
			$type = ASN1_TYPE_APPLICATION;
		}
		if( $checker & ASN1_CONSTRUCTED ) {
			$constructed = TRUE;
		}
		$ddd = false;
		if( !($type == ASN1_TYPE_CONTEXT_SPECIFIC && $constructed === FALSE) ) {
			$identifier = $this->getIdentifier( $identifier );
		}		
		if( ASN1_DEBUG ) echo 'identifier: ' . $identifier . PHP_EOL;
		
		$length = $this->readLength( !($constructed == TRUE && $type == ASN1_TYPE_CONTEXT_SPECIFIC) );
		if( ASN1_DEBUG ) echo 'Length: ' . $length . PHP_EOL;
		
		$start = count( $this->unpacked );
		$end = $start - $length;
		if( ($constructed == TRUE && $type == ASN1_TYPE_PRIVATE) || (!$trace && !$constructed && $type == ASN1_TYPE_CONTEXT_SPECIFIC) ) {
			if( ASN1_DEBUG ) echo 'cont[ ' . ($checker&~224) . ' ]' . PHP_EOL;
			$val = array();
			while( count($this->unpacked) > $end ) {
				$val[] = $this->parse( $trace );
			}
		} else if( $constructed == TRUE && $type == ASN1_TYPE_UNIVERSAL && $length == 48 ) {
			$continue = TRUE;
			if( ASN1_DEBUG ) echo PHP_EOL . PHP_EOL . 'STARTING SET' . PHP_EOL;
			$val = array();
			while( $continue ) {
				$offset = $this->readLength();
				$end = count($this->unpacked)-$offset;
				while( count($this->unpacked) > $end ) { 
					if( $this->unpacked[0] == '6' ) {
						$val[$this->parse($trace)] = $this->parse($trace);
					} else {
						$val[] = $this->parse($trace);
					}
				}
				$bits = $this->unpacked;
				$ignore = $this->getBit();
				$ignore = $this->getIdentifier( $ignore );
				$checklen = $this->readLength();
				if( $checklen != $length ) {
					if( ASN1_DEBUG ) echo 'ENDING SET' . PHP_EOL . PHP_EOL;
					$continue = false;
					$this->unpacked = $bits;
				} else {
					if( ASN1_DEBUG ) echo PHP_EOL . 'NEXT SET ELEMENT (' . $ignore . ')' . PHP_EOL;
				}
			}
		} else {
			switch( $identifier )
			{
				case '0': // bool
					print_r( $this->unpacked );
					break;
				case 'FF':
					$val = (bool)$identifier;
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '2': // integer
					$val = $this->readInteger( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '3': // BITSTRING
					$val = $this->readBitString( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '4': // OCTET STRING
					$val = $this->readOctetString( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '5': // integer
					$val = NULL;
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '6': // OBJECT
					$val = $this->readObjectIdentifier( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '13': // PrintableString
					$val = $this->readString( $length ); // get set length
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '15': // ISO646String
					$val = $this->readString( $length ); // get set length
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '16': // IA5String
					$val = $this->readString( $length ); // get set length
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '17': // UTCTIME
					$val = $this->readString( $length ); // get set length
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '30': // SEQUENCE
					$val = array();
					if($trace && ASN1_DEBUG) print_r( $this->unpacked );
					while( count($this->unpacked) > $end ) {
						if($trace && ASN1_DEBUG) print_r( $this->unpacked );
						$val[] = $this->parse( $trace );
					}
					break;
				// EXTENSIONS (subjectAltName)
				case '81':
					$val = 'email:' . $this->readString( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '82':
					$val = 'DNS:' . $this->readString( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '86':
					$val = 'URI:' . $this->readString( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				case '87':
					$val = 'IP:' . $this->readIPAddress( $length );
					if( ASN1_DEBUG ) var_dump( $val );
					break;
				default:
					for( $c=0;$c<$length;$c++ ) {
						$this->getBit( FALSE ); // throw away bits so we can keep going
					}
					if( ASN1_DEBUG ) {
						print_r(
							array(
								'identifier' => $identifier,
								'length' => $length,
						 		'type' => $type,
								'constructed' => $constructed,
							)
						);
					}
				break;
			}
		}
		return $val;
	}

	private function getIdentifier( $identifier )
	{
		$endOctet = FALSE;
		if( $identifier >= 31 ) {
			$identifierOctets = array();
			while( $endOctet === FALSE ) {
				$identifier = $this->getBit( FALSE );
				$identifierOctets[] = $identifier;
				if( hexdec($identifier) < 128 ) {
					$endOctet = TRUE;
				}
			}
			$identifier = implode( '.' , $identifierOctets );
		}
		return $identifier;
	}
	
	private function readString( $length )
	{
		$s = '';
		for( $i=0; $i<$length; $i++ ) {
			$s .= chr( $this->getBit( TRUE ) );
		}
		return $s;
	}
	
	private function readBitString( $length )
	{
		$s = '';
		for( $i=0; $i<$length; $i++ ) {
			$s .= $this->getBit( FALSE ) . ' ';
		}
		return $s;
	}
	
	private function readOctetString( $length )
	{
		$s = '';
		for( $i=0; $i<$length; $i++ ) {
			$s .= $this->getBit( FALSE ) . ' ';
		}
		return $s;
	}
	
	private function readIPAddress( $length )
	{
		$s = array();
		for( $i=0; $i<$length; $i++ ) {
			$s[] = chr( $this->getBit( TRUE ) );
		}
		return implode('.' , $s);
	}
	
	private function readLength()
	{
		$length = $this->getBit();
		if( ($length & 128) && $length < 132 ) {
			$lengthBits = $length-128;
			$lengthOctets = array();
			for( $i=0; $i<$lengthBits; $i++ ) {
				$lengthOctets[] = sprintf( '%08b', $this->getBit() );
			}
			$length = bindec(implode('', $lengthOctets ));
		}
		return $length;
	}
	
	private function readInteger( $length )
	{
		if( $length < 5 ) {
			$integer = array();
			for( $i=0; $i<$length; $i++ ) {
				$integer[] = sprintf( '%08b', $this->getBit() );
			}
			return bindec(implode('', $integer ));
		}
		$integer = array();
		for( $i=0; $i<$length; $i++ ) {
			$integer[] = sprintf( '%02X', $this->getBit() );
		}
		while( $integer[0] == '00' ) {
			array_shift($integer);
		}
		return implode( '' , $integer );
	}
	
	private function readObjectIdentifier( $length )
	{
		$objectIdentifier = array();
		$octetOne = $this->getBit();
		$objectIdentifier[] = floor( $octetOne / 40 );
		$objectIdentifier[] = $octetOne%40;
		$i = 1;
		while( $i<$length ) {
			$continue = TRUE;
			$subIdentifier = array();
			while( $continue ) {
				$nextOctet = $this->getBit();
				$i++;
				if( $nextOctet & 128 ) {
					$nextOctet -= 128;
				} else {
					$continue = FALSE;
				}
				$subIdentifier[] = sprintf( '%07b', $nextOctet );
			}
			$objectIdentifier[] = bindec(implode('', $subIdentifier ));
		}
		return $this->objectID( implode( '.', $objectIdentifier ) );
	}
	
	private function objectID( $oid )
	{
		if( isset( self::$_OIDS[$oid] ) ) {
			return self::$_OIDS[$oid];
		}
		return $oid;
	}
	
}
