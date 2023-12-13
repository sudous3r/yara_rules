/*
   YARA Rule Set
   Author: sud0us3er
   Date: 2023-12-05
   Identifier: suspicious-file
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Download_the_file__5835508_BCP_860_ {
   meta:
      description = "suspicious-file - file Download the file #5835508#BCP#860 .html"
      author = "sud0us3er"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-12-05"
      hash1 = "34a79a3065df03c84fab4cfea6382d043a1c30e10e36cbf3c92e00472623bcd3"
   strings:
      $s1 = "NTT0dERUlVVExFUEpSS0JBQlhZSEtLVkZEUVVHUUJKSklYR09USE9SV0VGUEYjNjUxMDQ2NjUg');\" /> " fullword ascii
      $s2 = "<body onload=\"document.location.href=window.atob('aHR0cHM6Ly9hdXRvZmFpci5nYW1lcy93bTNyIzI3ODE3OCNaWEFSV0FFVkxYSUFUTFRFRVhYUEVIW" ascii
      $s3 = "<body onload=\"document.location.href=window.atob('aHR0cHM6Ly9hdXRvZmFpci5nYW1lcy93bTNyIzI3ODE3OCNaWEFSV0FFVkxYSUFUTFRFRVhYUEVIW" ascii
   condition:
      uint16(0) == 0x623c and filesize < 1KB and
      all of them
}

