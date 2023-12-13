/*
   YARA Rule Set
   Author: sudous3er
   Date: 2023-12-13
   Identifier: sample
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule phishing {
   meta:
      description = "phising mail    #56170112#ZKSTZJPJHJGSTW#16885 .html"
      threat_level = 3
      author = "sudous3er"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-12-13"
      hash1 = "db857bb4c6f846d3495fa5a26b7bc9174f69f4ebc93ee384d6f1f873baa6617e"
   
   strings:
      $s1 = "HSVpHTlVVSVpRWUFaQllBS0xSVkFVSFVPUkhFVVhDQ0NFWk5RU0FVSVpTUkpDS0lZWVZLQkJSTkRWTFNPUllUWVlaUEtPQk9BWkVERlpMVyM1MjMg'));\" /> " fullword ascii
      $s2 = "<body onload=\"document.location.replace(window.atob('aHR0cHM6Ly9nZW5lZGFwcm9zcGVyaWRhZGUub25saW5lL3dudnAjNTgxMzIxMyNQWlFXVEZOSU" ascii
      $s3 = "<body onload=\"document.location.replace(window.atob('aHR0cHM6Ly9nZW5lZGFwcm9zcGVyaWRhZGUub25saW5lL3dudnAjNTgxMzIxMyNQWlFXVEZOSU" ascii
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      all of them
}

