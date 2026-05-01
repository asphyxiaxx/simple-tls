# Copyright (c) 2026 The simple-tls Contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the “Software”), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations

import typing

from ..io.serialization import Encoding, PublicFormat
from ..key import dh, ec, mlkem, x448, x25519
from ..utils.math import byte_length, bytes_to_int, int_to_bytes
from ._alert import (
    AlertDecodeError,
    AlertIllegalParameter,
    AlertInternalError,
)
from ._constant import ECC_GROUPS, NamedGroup


class _DHGroup:
    def __init__(
        self,
        name: str,
        p: int,
        g: int,
        q: int | None = None,
    ) -> None:
        self.name = name
        self.p = p
        self.g = g
        self.q = q  # typing.Optional


_RFC7919_FFDHE_GROUPS: dict[int, _DHGroup] = {
    NamedGroup.FFDHE2048: _DHGroup(
        name="ffdhe2048",
        p=int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
            "886B423861285C97FFFFFFFFFFFFFFFF",
            16,
        ),
        g=2,
        q=int(
            "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"
            "EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"
            "BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"
            "9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
            "CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"
            "98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"
            "DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"
            "8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
            "C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"
            "9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"
            "4435A11C30942E4BFFFFFFFFFFFFFFFF",
            16,
        ),
    ),
    NamedGroup.FFDHE3072: _DHGroup(
        name="ffdhe3072",
        p=int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
            "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
            "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
            "3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF",
            16,
        ),
        g=2,
        q=int(
            "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"
            "EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"
            "BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"
            "9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
            "CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"
            "98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"
            "DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"
            "8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
            "C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"
            "9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"
            "4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"
            "30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"
            "577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"
            "B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"
            "D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"
            "9E0D90771FEACEBE12F20E95B363171BFFFFFFFFFFFFFFFF",
            16,
        ),
    ),
    NamedGroup.FFDHE4096: _DHGroup(
        name="ffdhe4096",
        p=int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
            "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
            "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
            "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
            "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
            "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
            "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6A"
            "FFFFFFFFFFFFFFFF",
            16,
        ),
        g=2,
        q=int(
            "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"
            "EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"
            "BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"
            "9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
            "CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"
            "98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"
            "DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"
            "8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
            "C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"
            "9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"
            "4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"
            "30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"
            "577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"
            "B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"
            "D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"
            "9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"
            "BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"
            "43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"
            "5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"
            "0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"
            "C764DAAD3FC45235A6DAD428FA20C170E345003F2F32AFB5"
            "7FFFFFFFFFFFFFFF",
            16,
        ),
    ),
    NamedGroup.FFDHE6144: _DHGroup(
        name="ffdhe6144",
        p=int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
            "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
            "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
            "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
            "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
            "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
            "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"
            "0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"
            "3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"
            "CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
            "A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"
            "0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"
            "763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"
            "B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
            "D72B03746AE77F5E62292C311562A846505DC82DB854338A"
            "E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"
            "5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"
            "A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF",
            16,
        ),
        g=2,
        q=int(
            "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"
            "EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"
            "BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"
            "9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
            "CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"
            "98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"
            "DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"
            "8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
            "C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"
            "9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"
            "4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"
            "30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"
            "577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"
            "B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"
            "D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"
            "9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"
            "BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"
            "43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"
            "5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"
            "0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"
            "C764DAAD3FC45235A6DAD428FA20C170E345003F2F06EC81"
            "05FEB25B2281B63D2733BE961C29951D11DD2221657A9F53"
            "1DDA2A194DBB126448BDEEB258E07EA659C74619A6380E1D"
            "66D6832BFE67F638CD8FAE1F2723020F9C40A3FDA67EDA3B"
            "D29238FBD4D4B4885C2A99176DB1A06C500778491A8288F1"
            "855F60FFFCF1D1373FD94FC60C1811E1AC3F1C6D003BECDA"
            "3B1F2725CA595DE0CA63328F3BE57CC97755601195140DFB"
            "59D39CE091308B4105746DAC23D33E5F7CE4848DA316A9C6"
            "6B9581BA3573BFAF311496188AB15423282EE416DC2A19C5"
            "724FA91AE4ADC88BC66796EAE5677A01F64E8C0863139582"
            "2D9DB8FCEE35C06B1FEEA5474D6D8F34B1534A936A18B0E0"
            "D20EAB86BC9C6D6A5207194E68720732FFFFFFFFFFFFFFFF",
            16,
        ),
    ),
    NamedGroup.FFDHE8192: _DHGroup(
        name="ffdhe8192",
        p=int(
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
            "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
            "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
            "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
            "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
            "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
            "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
            "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
            "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
            "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
            "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
            "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
            "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
            "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
            "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
            "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
            "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
            "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
            "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"
            "0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"
            "3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"
            "CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
            "A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"
            "0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"
            "763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"
            "B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
            "D72B03746AE77F5E62292C311562A846505DC82DB854338A"
            "E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"
            "5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"
            "A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838"
            "1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E"
            "0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665"
            "CB2C0F1CC01BD70229388839D2AF05E454504AC78B758282"
            "2846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022"
            "BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C"
            "51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9"
            "D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA457"
            "1EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30"
            "FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D"
            "97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88C"
            "D68C8BB7C5C6424CFFFFFFFFFFFFFFFF",
            16,
        ),
        g=2,
        q=int(
            "7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78"
            "EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7C"
            "BE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B0"
            "9219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
            "CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A"
            "98566527A41D3CBD5E0558C159927DB0E88454A5D96471FD"
            "DCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C"
            "8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
            "C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B9"
            "9DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD"
            "4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C"
            "30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E"
            "577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9"
            "B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06"
            "D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF7"
            "9E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7D"
            "BC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A002"
            "43FAADD2BF18E63D389AE44377DA18C576B50F0096CF3419"
            "5483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD"
            "0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7"
            "C764DAAD3FC45235A6DAD428FA20C170E345003F2F06EC81"
            "05FEB25B2281B63D2733BE961C29951D11DD2221657A9F53"
            "1DDA2A194DBB126448BDEEB258E07EA659C74619A6380E1D"
            "66D6832BFE67F638CD8FAE1F2723020F9C40A3FDA67EDA3B"
            "D29238FBD4D4B4885C2A99176DB1A06C500778491A8288F1"
            "855F60FFFCF1D1373FD94FC60C1811E1AC3F1C6D003BECDA"
            "3B1F2725CA595DE0CA63328F3BE57CC97755601195140DFB"
            "59D39CE091308B4105746DAC23D33E5F7CE4848DA316A9C6"
            "6B9581BA3573BFAF311496188AB15423282EE416DC2A19C5"
            "724FA91AE4ADC88BC66796EAE5677A01F64E8C0863139582"
            "2D9DB8FCEE35C06B1FEEA5474D6D8F34B1534A936A18B0E0"
            "D20EAB86BC9C6D6A5207194E67FA35551B5680267B00641C"
            "0F212D18ECA8D7327ED91FE764A84EA1B43FF5B4F6E8E62F"
            "05C661DEFB258877C35B18A151D5C414AAAD97BA3E499332"
            "E596078E600DEB81149C441CE95782F22A282563C5BAC141"
            "1423605D1AE1AFAE2C8B0660237EC128AA0FE3464E435811"
            "5DB84CC3B523073A28D4549884B81FF70E10BF361C137296"
            "28D5348F07211E7E4CF4F18B286090BDB1240B66D6CD4AFC"
            "EADC00CA446CE05050FF183AD2BBF118C1FC0EA51F97D22B"
            "8F7E46705D4527F45B42AEFF395853376F697DD5FDF2C518"
            "7D7D5F0E2EB8D43F17BA0F7C60FF437F535DFEF29833BF86"
            "CBE88EA4FBD4221E8411728354FA30A7008F154A41C7FC46"
            "6B4645DBE2E321267FFFFFFFFFFFFFFF",
            16,
        ),
    ),
}


class FFDHKeyExchange:
    def __init__(
        self,
        group: int = NamedGroup.FFDHE2048,
        parameters: dh.DHParameters | None = None,
    ) -> None:
        if parameters is None:
            try:
                dh_group = _RFC7919_FFDHE_GROUPS[group]
            except KeyError:
                raise AlertInternalError(f"Unsupport dh group '{group}")

            parameter_numbers = dh.DHParameterNumbers(
                p=dh_group.p,
                g=dh_group.g,
                q=dh_group.q,
            )
            parameters = parameter_numbers.parameters()
        else:
            parameter_numbers = parameters.parameter_numbers()

        private_key = parameters.generate_private_key()
        self._parameter_numbers = parameter_numbers
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @property
    def y(self):
        return self._public_key.public_numbers().y

    @property
    def p(self):
        return self._parameter_numbers.p

    @property
    def g(self):
        return self._parameter_numbers.g

    def generate_key_share(self) -> bytes:
        p = self.p
        y = self.y
        return int_to_bytes(y, byte_length(p))

    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        y = bytes_to_int(peer_public, "big")

        peer_public_numbers = dh.DHPublicNumbers(y, self._parameter_numbers)
        peer_public_key = peer_public_numbers.public_key()
        try:
            return self._private_key.exchange(peer_public_key)
        except ValueError as exc:
            raise AlertIllegalParameter(str(exc))

    def generate_and_compute(self, peer_public: bytes) -> tuple[bytes, bytes]:
        return (
            self.generate_key_share(),
            self.compute_shared_secret(peer_public),
        )


_NAMEDGROUP_TO_CURVE: dict[int, ec.EllipticCurve] = {
    NamedGroup.SECP192R1: ec.SECP192R1(),
    NamedGroup.SECP224R1: ec.SECP224R1(),
    NamedGroup.SECP256R1: ec.SECP256R1(),
    NamedGroup.SECP384R1: ec.SECP384R1(),
    NamedGroup.SECP521R1: ec.SECP521R1(),
}


class ECDHKeyExchange:
    def __init__(self, group: int) -> None:
        if group not in ECC_GROUPS:
            raise AlertInternalError("Invalid group for EC curve'%s'" % group)

        private_key: typing.Union[
            x25519.X25519PrivateKey,
            x448.X448PrivateKey,
            ec.EllipticCurvePrivateKey,
        ]
        if group == NamedGroup.X25519:
            private_key = x25519.X25519PrivateKey.generate()
        elif group == NamedGroup.X448:
            private_key = x448.X448PrivateKey.generate()
        else:
            try:
                ec_curve = _NAMEDGROUP_TO_CURVE[group]
            except KeyError:
                raise AlertInternalError("Unsupported curve")
            private_key = ec.generate_private_key(ec_curve)

        self._private_key = private_key
        self._public_key = private_key.public_key()

    def generate_key_share(self) -> bytes:
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
        else:
            return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        try:
            if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
                algorithm = ec.ECDH()
                pk_ec = ec.EllipticCurvePublicKey.from_encoded_point(
                    self._private_key.curve, peer_public
                )
                return self._private_key.exchange(algorithm, pk_ec)

            elif isinstance(self._private_key, x25519.X25519PrivateKey):
                pk_x25519 = x25519.X25519PublicKey.from_public_bytes(peer_public)
                return self._private_key.exchange(pk_x25519)

            elif isinstance(self._private_key, x448.X448PrivateKey):
                pk_x448 = x448.X448PublicKey.from_public_bytes(peer_public)
                return self._private_key.exchange(pk_x448)

            else:
                raise AlertInternalError(
                    "Unsupported private key type for key exchange."
                )

        except ValueError as exc:
            raise AlertDecodeError(str(exc))

    def generate_and_compute(self, peer_public: bytes) -> tuple[bytes, bytes]:
        return (
            self.generate_key_share(),
            self.compute_shared_secret(peer_public),
        )


_EC_KEY_LEN: dict[int, int] = {
    NamedGroup.X25519MLKEM768: 32,
    NamedGroup.SECP256R1MLKEM768: 65,
    NamedGroup.SECP384R1MLKEM1024: 97,
}

_PQC_KEY_LEN: dict[int, int] = {
    NamedGroup.X25519MLKEM768: 1184,
    NamedGroup.SECP256R1MLKEM768: 1184,
    NamedGroup.SECP384R1MLKEM1024: 1568,
}

_PQC_CIPHERTEXT_LEN: dict[int, int] = {
    NamedGroup.X25519MLKEM768: 1088,
    NamedGroup.SECP256R1MLKEM768: 1088,
    NamedGroup.SECP384R1MLKEM1024: 1568,
}


class KEMKeyExchange:
    def __init__(self, group: int) -> None:
        pqc_private_key: typing.Union[
            mlkem.MLKEM768PrivateKey,
            mlkem.MLKEM1024PrivateKey,
        ]
        if group == NamedGroup.X25519MLKEM768:
            curve = NamedGroup.X25519
            pqc_private_key = mlkem.MLKEM768PrivateKey.generate()
        elif group == NamedGroup.SECP256R1MLKEM768:
            curve = NamedGroup.SECP256R1
            pqc_private_key = mlkem.MLKEM768PrivateKey.generate()
        elif group == NamedGroup.SECP384R1MLKEM1024:
            curve = NamedGroup.SECP384R1
            pqc_private_key = mlkem.MLKEM1024PrivateKey.generate()
        else:
            raise AlertInternalError("Unknown KEM group '%s'" % group)

        self._group = group
        self._ec_kex = ECDHKeyExchange(curve)

        self._private_key = pqc_private_key
        self._public_key = pqc_private_key.public_key()

    def generate_key_share(self) -> bytes:
        pqc_pk = self._public_key.public_bytes_raw()
        ec_pk = self._ec_kex.generate_key_share()

        if self._group == NamedGroup.X25519MLKEM768:
            key_share = pqc_pk + ec_pk
        else:
            key_share = ec_pk + pqc_pk
        return key_share

    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        expected_pqc_ct_len = _PQC_CIPHERTEXT_LEN[self._group]
        peer_pqc_ct, peer_ec_pk = self._split_pk(peer_public, expected_pqc_ct_len)

        ec_ss = self._ec_kex.compute_shared_secret(peer_ec_pk)
        try:
            pqc_ss = self._private_key.decapsulate(peer_pqc_ct)
        except ValueError as exc:
            raise AlertDecodeError(str(exc))

        if self._group == NamedGroup.X25519MLKEM768:
            shared_secret = pqc_ss + ec_ss
        else:
            shared_secret = ec_ss + pqc_ss

        return shared_secret

    def generate_and_compute(self, peer_public: bytes) -> tuple[bytes, bytes]:
        expected_pqc_pk_len = _PQC_KEY_LEN[self._group]
        peer_pqc_pk, peer_ec_pk = self._split_pk(peer_public, expected_pqc_pk_len)

        ec_pk, ec_ss = self._ec_kex.generate_and_compute(peer_ec_pk)

        peer_pqc_pubkey: typing.Union[
            mlkem.MLKEM768PublicKey,
            mlkem.MLKEM1024PublicKey,
        ]
        if self._group == NamedGroup.SECP384R1MLKEM1024:
            peer_pqc_pubkey = mlkem.MLKEM1024PublicKey.from_public_bytes(peer_pqc_pk)
        else:
            peer_pqc_pubkey = mlkem.MLKEM768PublicKey.from_public_bytes(peer_pqc_pk)

        try:
            pqc_ss, pqc_ct = peer_pqc_pubkey.encapsulate()
        except ValueError as exc:
            raise AlertIllegalParameter(str(exc))

        if self._group == NamedGroup.X25519MLKEM768:
            key_share = pqc_ct + ec_pk
            shared_secret = pqc_ss + ec_ss
        else:
            key_share = ec_pk + pqc_ct
            shared_secret = ec_ss + pqc_ss

        return key_share, shared_secret

    def _split_pk(self, pk: bytes, pqc_data_len: int) -> tuple[bytes, bytes]:
        ec_key_len = _EC_KEY_LEN[self._group]

        if len(pk) != ec_key_len + pqc_data_len:
            raise AlertIllegalParameter(
                f"Invalid key size '{len(pk)}' for the selected group. "
                f"Expected '{ec_key_len + pqc_data_len}'."
            )

        if self._group == NamedGroup.X25519MLKEM768:
            pqc_data = pk[:pqc_data_len]
            ec_pk = pk[-ec_key_len:]
        else:
            pqc_data = pk[-pqc_data_len:]
            ec_pk = pk[:ec_key_len]

        return pqc_data, ec_pk
