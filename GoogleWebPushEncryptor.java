import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A quick hack to use Google Cloud Messaging with Payload (i.e. Encryption) until Google release an official library.
 * 
 * Based on instructions from Google and all credits should go there:
 * 
 * https://developers.google.com/web/updates/2016/03/web-push-encryption?hl=en
 * https://tests.peter.sh/push-encryption-verifier/
 * 
 * @author M Roth
 */
public class GoogleWebPushEncryptor {

	static final Logger log = LoggerFactory.getLogger(GoogleWebPushEncryptor.class);

	private KeyPairGenerator _keyGen;
	private KeyFactory _keyFactory;
	private ECNamedCurveParameterSpec _ecSpec;

	@PostConstruct
	private void init() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			_keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
			_keyFactory = KeyFactory.getInstance("ECDH", "BC");
			_ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			_keyGen.initialize(_ecSpec);
		} catch (Exception ex) {
			log.error("Failed initializing Web Push Encryptor", ex);
		}
	}

	public GoogleWebPushCrypto encrypt(String remoteKey_, String remoteAuth_, String payload_)
			throws IOException, GeneralSecurityException {
		KeyPair localKeyPair = _keyGen.generateKeyPair();
		byte[] saltBytes = new byte[16];
		new SecureRandom().nextBytes(saltBytes);

		PrivateKey localPrivateKey = localKeyPair.getPrivate();
		PublicKey localPublicKey = localKeyPair.getPublic();
		byte[] pubKeyBytes = ((ECPublicKey) localPublicKey).getQ().getEncoded();
		String pubKeyStr = Base64.encodeBase64URLSafeString(pubKeyBytes);// P-256 uncompressed EC point
		pubKeyBytes = Base64.decodeBase64(pubKeyStr);

		byte[] remoteKeyBytes = Base64.decodeBase64(remoteKey_);
		ECPoint remotePoint = _ecSpec.getCurve().decodePoint(remoteKeyBytes);
		ECPublicKeySpec remoteSpec = new ECPublicKeySpec(remotePoint, _ecSpec);
		ECPublicKey remoteKey = (ECPublicKey) _keyFactory.generatePublic(remoteSpec);

		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
		keyAgreement.init(localPrivateKey);
		keyAgreement.doPhase(remoteKey, true);
		SecretKey sharedKey = keyAgreement.generateSecret("AES");

		String saltStr = Base64.encodeBase64String(saltBytes);

		log.debug("pub: " + pubKeyStr);
		log.debug("slt: " + saltStr);
		log.debug("aut: " + remoteAuth_);

		// NOTE: Uncomment for debug
		// BigInteger pbi = ((ECPrivateKey) localPrivateKey).getS();
		// String privKeyStr = _codecB64.encodeAsString(pbi.toByteArray()); // 32-octet point
		// String sharedStr = _codecB64.encodeAsString(sharedKey.getEncoded());
		// log.debug("pri: " + privKeyStr);
		// log.debug("cli: " + remoteKey_);
		// log.debug("ikm: " + sharedStr);

		// Pseudo-Random Key PRK
		byte[] authb = "Content-Encoding: auth".getBytes("UTF-8");
		byte[] authbytes = Arrays.copyOf(authb, authb.length + 1);
		byte[] prk = hkdf(Base64.decodeBase64(remoteAuth_.getBytes()), sharedKey.getEncoded(), authbytes, 32);

		// Content Encryption Key CEK
		byte[] cekInfoBytes = createInfo("aesgcm", remoteKeyBytes, pubKeyBytes);
		final byte[] cek = hkdf(saltBytes, prk, cekInfoBytes, 16);
		// NONCE
		byte[] nonceInfoBytes = createInfo("nonce", remoteKeyBytes, pubKeyBytes);
		final byte[] nonce = hkdf(saltBytes, prk, nonceInfoBytes, 12);

		// NOTE: Uncomment for debug
		// String prkStr = _codecB64.encodeAsString(prk);
		// String cekInfoStr = _codecB64.encodeAsString(cekInfoBytes);
		// String nonceInfoStr = _codecB64.encodeAsString(nonceInfoBytes);
		// String cekStr = _codecB64.encodeAsString(cek);
		// String nonceStr = _codecB64.encodeAsString(nonce);
		// log.debug("prk: " + prkStr);
		// log.debug("cki: " + cekInfoStr);
		// log.debug("cek: " + cekStr);
		// log.debug("nni : " + nonceInfoStr);
		// log.debug("non: " + nonceStr);

		byte[] plb;
		if (StringUtils.isEmpty(payload_)) {
			plb = new byte[2];
		} else {
			plb = payload_.getBytes();
			ByteBuffer bb = ByteBuffer.allocate(plb.length + 2);
			bb.position(2);
			bb.put(plb);
			plb = bb.array();
		}

		SecretKeySpec key = new SecretKeySpec(cek, "AES-GCM");
		AlgorithmParameterSpec spec = new IvParameterSpec(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		byte[] cipherBytes = cipher.doFinal(plb);
		String cipherStr = Base64.encodeBase64String(cipherBytes); // NOTE: Do NOT encode URL-safe
		log.debug("end: " + cipherStr);

		Map<String, String> headerMap = new HashMap<>();
		headerMap.put("Encryption", "salt=" + saltStr);
		headerMap.put("Crypto-Key", "dh=" + pubKeyStr);
		headerMap.put("Content-Encoding", "aesgcm");

		GoogleWebPushCrypto result = new GoogleWebPushCrypto();
		result.setMessage(cipherStr);
		result.setSecHeaders(headerMap);

		return result;
	}

	static private byte[] createInfo(String type_, byte[] remoteKey_, byte[] pubKey_) {
		int len = type_.length();

		// The start index for each element within the buffer is:
		// value | length | start |
		// -----------------------------------------
		// 'Content-Encoding: '| 18 | 0 |
		// type | len | 18 |
		// nul byte | 1 | 18 + len |
		// 'P-256' | 5 | 19 + len |
		// nul byte | 1 | 24 + len |
		// client key length | 2 | 25 + len |
		// client key | 65 | 27 + len |
		// server key length | 2 | 92 + len |
		// server key | 65 | 94 + len |
		// For the purposes of push encryption the length of the keys will
		// always be 65 bytes.

		ByteBuffer info = ByteBuffer.allocateDirect(18 + len + 1 + 5 + 1 + 2 + 65 + 2 + 65);
		info.put("Content-Encoding: ".getBytes());// The string 'Content-Encoding: ', as utf-8
		info.put(type_.getBytes());// The 'type' of the record, a utf-8 string
		info.put((byte) '\0');// A single null-byte
		info.put("P-256".getBytes());// The string 'P-256', declaring the elliptic curve being used
		info.put((byte) '\0');// A single null-byte
		info.putShort((short) remoteKey_.length);// The length of the client's public key as a 16-bit integer
		info.put(remoteKey_); // Now the actual client public key
		info.putShort((short) pubKey_.length);// Length of our public key
		info.put(pubKey_);// The key itself

		info.position(0);
		byte[] result = new byte[info.capacity()];
		info.get(result);
		return result;
	}

	private static byte[] hkdf(byte[] salt_, byte[] ikm_, byte[] info_, int length_) throws GeneralSecurityException {
		if (length_ > 32) {
			throw new GeneralSecurityException(
					String.format("Cannot return keys of more than 32 bytes, [%d] requested", length_));
		}
		// Extract
		Mac keyHmac = Mac.getInstance("HmacSHA256", "BC");
		keyHmac.init(new SecretKeySpec(salt_, "HmacSHA256"));
		keyHmac.update(ikm_);
		byte[] key = keyHmac.doFinal();

		// Expand
		Mac infoHmac = Mac.getInstance("HmacSHA256", "BC");
		infoHmac.init(new SecretKeySpec(key, "HmacSHA256"));
		infoHmac.update(info_);
		infoHmac.update((byte) 1);
		byte[] key_bytes = infoHmac.doFinal();

		byte[] result = Arrays.copyOf(key_bytes, length_);
		return result;
	}

	public static class GoogleWebPushCrypto {

		private String message;
		private Map<String, String> secHeaders;

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}

		public Map<String, String> getSecHeaders() {
			return secHeaders;
		}

		public void setSecHeaders(Map<String, String> secHeaders) {
			this.secHeaders = secHeaders;
		}
	}
}
