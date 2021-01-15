using Microsoft.IdentityModel.Tokens;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;

namespace Sievo.Security
{
    public static class JwtToken
    {
        public static string Create()
        {
            using (var rsaCryptoProvider = new RSACryptoServiceProvider())
            {
                var rsaParams = CreateRsaParameters();
                rsaCryptoProvider.ImportParameters(rsaParams);
                var key = new RsaSecurityKey(rsaCryptoProvider);
                var tokenHandler = new JwtSecurityTokenHandler();
                var claims = new Dictionary<string, object>() { { "some", "thing" } };

                var desc = new SecurityTokenDescriptor
                {
                    Claims = claims,
                    SigningCredentials = new SigningCredentials(
                        key,
                        SecurityAlgorithms.RsaSha256Signature)
                };

                var token = tokenHandler
                    .CreateJwtSecurityToken(desc);

                var result = tokenHandler.WriteToken(token);

                return result;
            }
        }

        private static RSAParameters CreateRsaParameters()
        {
            //key generated using https://travistidwell.com/jsencrypt/demo/
            using var privateKeyReader = new StringReader(@"-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBI7jWig2fuMbhkDbyOgGf88gnR9SLqdnHxOJ9zGeb38a89rKQS
2AMKftUMrQ/gKvOUK3UMlvLjXDl1IVOzTvgpi3glTR5aT6UieKEilOBxPzvpRZx3
I3HPIGzNqq9Mve4DMB15JIswsy8SEN1ErypeWD26CnygP924Y0st1VhlvC+J2G1Q
Mq2hFAqmmFUh+V6tC3KMdHRvjyuH0pgoVNhQ7/h0OFSeYisDgparI+T5N9nATyGf
evGH/gfnfu0css3ccRHe/U3m0hDi2p0+fpMuQ9j5cE4hnX/Acbm5szCZMSlEautd
f5a/Maxblx7oR0jxxf7UR36skjiautF2BsRTAgMBAAECggEAKpheYRWIrRkDDgTr
3ProQVcIH0WiZ/hX4kBk+G/nc2cIJ+heR9c8J3QecPHfNNlBPIgJLBo5sEscD+ow
HakAzhr0SCz7jlm4JCL6Ud1MHTiGgF803GyqOwRAJ/sJubOwgNIoVKngVchBtLZ+
1W/NOh8lpjQbx+ilUd1EeneB0qDwA7Cwe3yuFCraXpJDViL17URdeBLxHdxgeRgH
0HgBti7fj2ll0nl+qv1lDsNMp58qVUSMKs/tZLr5kQ+gbLbejJnOLpGzbhjOoVjb
KX4065vpzx+tkneBkcdtK+vvGxf1Yy4oyCxCi0g8sRd+Qep/D3jk5L4he0Sa0k7q
bSfNaQKBgQCPWFjFwqfSaBpSrutWTXi9YOv8OKjcxxX/AK+Hs8XpCStB9hEuFmkL
AKuwen4UH5MBYCbo5FMYKPbJpEXUXgQ4BO78PZp4TfCPB7P22T7QSLANoQkk83LN
QYeE/g6TFmuYON986VGzHIZ5XBPTzfxcceWC8sxO1yCnKBm/dj7+PQKBgQCCPx/Q
IpJv1TrRIA+XhDkskZA5pLLHQHoYO6pKl25lW3e1OhGGvzHP9UaMwX739m/2ec6G
VKBp9prM8HoI5gM9y/LhbWgyvlpIWBnuuZA3XUneOb3TwJ2IEIqWMjjetnvOnxSL
UvdGsh6kernuxw+gnCeJJUxa+CJY3ftBGKAFzwKBgD8NMkcSnzUKu4FhFX0pqJFM
f6C633P1UjSPfaYoKkad1Nw3u0jVbLD9Q4fl6W06kjQJsjPAstgutJbvXhPSovJt
IR3sjvSZ+9U+IyfSWTHOtznXeqk5OGcWiuCxy4FhXERhx9Qu4NPzGSdqnAIPWhDj
vHuEBuAq+l7sYZ75CS5VAoGAO0kOawgBjeQKNLyaPEaUW8QaWRKtyeKAcN1fwzow
pvQ+hgBbj/EhdF5Z8aH18Fp9VjzVk/GbXwBAMD7Z3YkNOqjF8nSBdG+O2tU3YKGY
korlH8E6tdM8IX4eBwXvOvjnXAKvMEfghI55QjcWwShc5aeOm2+d1N6Ti83nGxdh
Z6MCgYBIu/IX7cVSZOHu7vYZb/MwytrI4YtFzufCBhG4M0InH1Cuju/4L5+CYcga
8zxGmZiK7Q0KZxmOY1Ngm41GGFfjpRC5JsaGyHQcefhzMFwM8/onMwMYZDNDELjm
qhQHBYuV4MycIP4QOKow6GOik4KTuQbq8XPIMTDgUbbzPduRnw==
-----END RSA PRIVATE KEY-----");

            var pemReader = new PemReader(privateKeyReader);

            if (!(pemReader.ReadObject() is AsymmetricCipherKeyPair keyPair))
            {
                throw new Exception("Could not read RSA private key");
            }

            return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
        }
    }
}
