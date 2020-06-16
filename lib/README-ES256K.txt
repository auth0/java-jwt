
How to create a secp256k1 key to be used with ES256K algorithm:

## first we generate the key
openssl ecparam -genkey -name secp256k1 -out KEY.pem -text
## the file is split into 2 parts a curve specification (EC PARAMETERS) and the key value
## this format is not suitable to be read by the PermUtils PEM reader so we have to convert it
## into PCKS8 format:

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in KEY.pem -out ec256k-key.private.pem

## the public key is then calculated as follows:
openssl ec -pubout -in KEY.pem -out ec256k-key-public.pem

##
## how to get DER signature
ECDSAAlgorithm algorithm256 = (ECDSAAlgorithm) Algorithm.ECDSA256((ECPublicKey) readPublicKeyFromFile(PUBLIC_KEY_FILE_256K, "EC"), (ECPrivateKey) readPrivateKeyFromFile(PRIVATE_KEY_FILE_256K, "EC"));
String[] parts = ES256K_JWT.split("\\.");

byte[] derSignature = algorithm256.JOSEToDER(Base64.decodeBase64(parts[2]));
String jwt=parts[0]+"."+parts[1]+"."+Base64.encodeBase64URLSafeString(derSignature);
