# Sliver-CPPImplant2

Code for a C++ implant compatible with my fork [refactor/teamserver-interaction](https://github.com/MrAle98/sliver/tree/refactor/teamserver-interaction) of sliver C2. For me it was an exercise to learn C++.
It may teach you how to **NOT** write code in C++. For sure It has issues.

## Supported commands

* pwd
* execute-assembly with flag -i. It support only in process execute assembly. etw bypass and amsi bypass are applied by default with old technique of patching. 
* cd
* ls
* upload
* download
* mkdir
* rm
* make-token
* rev2self
* execute
* impersonate
* list-tokens
* ps
* execute extensions DLL
* execute BOFs
* pivot commands

## Debugging

Create a vckpg.json file with the following content:

```
{
  "dependencies": [
    "botan",
    "cpr",
    "gzip-hpp",
    "libsodium",
    "protobuf",
    "stduuid"
  ],
  "overrides": [
    {
      "name": "botan",
      "version": "2.19.3"
    },
    {
      "name": "cpr",
      "version": "1.9.2"
    },
    {
      "name": "gzip-hpp",
      "version": "0.1.0#1"
    },
    {
      "name": "libsodium",
      "version": "1.0.18#8"
    },
    {
      "name": "protobuf",
      "version": "3.21.8"
    },
    {
      "name": "stduuid",
      "version": "1.2.2"
    }
  ]
}
```

Run the following powershell commands:
```
mkdir C:\vcpkg
mv vcpkg.json C:\vcpkg
cd C:\vcpkg
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
cd vcpkg
.\vcpkg.exe integrate install
cd ..
.\vcpkg\vcpkg.exe x-update-baseline --add-initial-baseline
.\vcpkg\vcpkg.exe install --triplet=x64-windows-static --host-triplet=x64-windows-static --allow-unsupported
cd C:\vcpkg\vcpkg
$cmake_path=gci -force -Recurse -Include "cmake.exe" | select -ExpandProperty DirectoryName
setx PATH "$cmake_path;$env:path" -m
```

Generate an executable in sliver and retrieve the keys from implant.go.
```
# cat ~/.sliver/slivers/windows/amd64/MENTAL_SWITCHBOARD/src/github.com/bishopfox/sliver/implant/sliver/cryptography/implant.go 
package cryptography

[...]
var (
        // ECCPublicKey - The implant's ECC public key
        ECCPublicKey = "BMUu6mff0UUWMxF1urNVX0C8oTl58YE+HrIdpm978iU"
        // eccPrivateKey - The implant's ECC private key
        eccPrivateKey = "UVuPU6F4OkwhcaBW0TxbVv6SsEZG8IaKv8OKOE7qLLA"
        // eccPublicKeySignature - The implant's public key minisigned'd
        ECCPublicKeySignature = `untrusted comment: signature from private key: A14D189CBA4E22A5
RWSlIk66nBhNoZXFDVCnCVYXzT/VuGz05ZAbVlCKkAlXLXf/dgULYNR04KNj7QLX2Qtv27xQZtw+cW1jo2ujYSw+kUkezsKTQwk=
trusted comment: timestamp:1724166512
90Vwz17/+55kCNZ1ERhMx7QuC5hSTFE3I1z3+dKT2PdWPJ7h8z2MHddPkAmVpnhFHPuDj+wb1wgjkValnu7RAw==`
        // eccServerPublicKey - Server's ECC public key
        eccServerPublicKey = "F5Cn0lcoMnPzt1IgxCxiLL+JkI0zxA5u5Rh0y7Ps0G8"
        // minisignServerPublicKey - The server's minisign public key
        minisignServerPublicKey = `untrusted comment: minisign public key: A14D189CBA4E22A5
RWSlIk66nBhNobryxxyTH5ylIygxN1+W8V5l+b6TU5/dFSsuiNS61VY4`

        // TOTP secret value
        totpSecret = "3Q6ZFBYFYEVYC3C6OU2HUCFIJ46TM3B3"

        // ErrInvalidPeerKey - Peer to peer key exchange failed
        ErrInvalidPeerKey = errors.New("invalid peer key")
)

// 

// GetECCKeyPair - Get the implant's key pair
func GetECCKeyPair() *ECCKeyPair {
        publicRaw, err := base64.Raw
[...]
```

Take just `eccServerPublicKey`, `eccPublicKey`, `eccPrivateKey`, `totpsecret` and set them inside src/CryptoUtils.cpp.
```
#include "CryptoUtils.h"

namespace crypto {
#ifdef DEBUG
    string eccServerPublicKey = "zKn2nDnphmQImAjQ+UmueLUdACvWBb02Voet943Huhc";
    // ECCPublicKey - The implant's ECC public key
    string eccPublicKey = "+UpkonzIDtgnuWkC8HXZkfb6xiXvgKWvbCA4Ii9kRjw";
    // eccPrivateKey - The implant's ECC private key
    string eccPrivateKey = "s+JQAl9lb2+Puj9B3k6PSaDMtbacUb0P5QZTGXhaTog";
    string totpsecret = "TZLMFPN6HDMZGIVSDSP7UNQNG3BNCO3Y";
#else
[...]
```
