rule MIME_MSO_ActiveMime_base64
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-23"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime01 = "QWN0aXZlTW" // { 51 57 4E 30 61 58 5A 6C 54 57 }
		$activemime02 = { 51 0D 0A 57 4E 30 61 58 5A 6C 54 57 }
		$activemime03 = { 51 0D 0A 57 0D 0A 4E 30 61 58 5A 6C 54 57 }
		$activemime04 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 61 58 5A 6C 54 57 }
		$activemime05 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 58 5A 6C 54 57 }
		$activemime06 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 0D 0A 58 5A 6C 54 57 }
		$activemime07 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 0D 0A 58 0D 0A 5A 6C 54 57 }
		$activemime08 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 0D 0A 58 0D 0A 5A 0D 0A 6C 54 57 }
		$activemime09 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 0D 0A 58 0D 0A 5A 0D 0A 6C 0D 0A 54 57 }
		$activemime10 = { 51 0D 0A 57 0D 0A 4E 0D 0A 30 0D 0A 61 0D 0A 58 0D 0A 5A 0D 0A 6C 0D 0A 54 0D 0A 57 }
	
	condition:
	 	($mime at 0 and $base64 and $mso and any of ($activemime*))
}