package com.example.authtag.ecdhexample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.params.HKDFParameters;
import org.spongycastle.crypto.util.PublicKeyFactory;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import de.frank_durr.ecdh_curve25519.ECDHCurve25519;

import static com.example.authtag.ecdhexample.R.id.textView5;


public class MainActivity extends AppCompatActivity {

    static final String TAG = "DEBUG";
    static {
        // Load native library ECDH-Curve25519-Mobile implementing Diffie-Hellman key
        // exchange with elliptic curve 25519.
        try {
            System.loadLibrary("ecdhcurve25519");
            Log.i(TAG, "Loaded ecdhcurve25519 library.");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Error loading ecdhcurve25519 library: " + e.getMessage());
        }
    }

    private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[32];
        random.nextBytes(salt);

        return salt;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tw = (TextView) findViewById(textView5);

//        SecureRandom random = new SecureRandom();
//        byte[] tag_owner_secret_key = ECDHCurve25519.generate_secret_key(random);

        /* Use test vector for Tags owner private key  */
        byte[] tag_owner_secret_key = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

        /* Create Tags owner public key. */
        byte[] tag_owner_public_key = ECDHCurve25519.generate_public_key(tag_owner_secret_key);

        /* Tag Public key have to be read from tag via UnlockPublicKey characteristic of
         * tag's configuration service  */

        /* Use test vector for Tag public key */
        byte[] tag_public_key = Hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        /* Calculate the shared secret. */
        byte[] shared_secret = ECDHCurve25519.generate_shared_secret(
                tag_owner_secret_key, tag_public_key);

        /*  The salt is both public keys concetenation  */
        byte[] salt = new byte[ tag_owner_public_key.length + tag_public_key.length  ];
        System.arraycopy(tag_owner_public_key,0,salt,0,tag_owner_public_key.length);
        System.arraycopy(tag_public_key,0,salt,tag_owner_public_key.length,tag_public_key.length);

        /* Calculate UnlockCode  */
        Digest digest = new SHA256Digest();
        HKDFBytesGenerator kDFBytesGenerator = new HKDFBytesGenerator(digest);
        kDFBytesGenerator.init(new HKDFParameters(
                shared_secret, /*IKM*/
                salt, /*SALT*/
                null /* info */
        ));

        byte[] raw_unlock_code = new byte[32];
        kDFBytesGenerator.generateBytes(raw_unlock_code, 0, 32);
        byte[] unlock_code = new byte[16];
        System.arraycopy(raw_unlock_code,0,unlock_code,0, 16);
        /* Unlock code : 73e3da79c695d1629d9b62c2a801a7ff */
        Log.d(TAG, "UnlockCode is: \n" + Hex.toHexString(unlock_code) );
        tw.setText("Tag's owner private key: \n" + Hex.toHexString(tag_owner_secret_key) + "\n" +
                   "Tag's public key: \n" + Hex.toHexString(tag_public_key) + "\n" +
                   "Shared secret: \n" + Hex.toHexString(shared_secret) + "\n" +
                   "Unlock Code: \n" + Hex.toHexString(unlock_code) + "\n"  );



        byte[] pubKey = Hex.decode("04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f");
        byte[] message = new byte[0];
        try {
            message = "Maarten Bodewes generated this test vector on 2016-11-08".getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        byte[] signature = Hex.decode("30440220241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f7950220021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e");

        Enumeration curves = ECNamedCurveTable.getNames();
        while (curves.hasMoreElements()) {
            Log.d(TAG, "U " + curves.nextElement()  );
        }

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("ECDSA",new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = null;
        try {
            pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        Signature ecdsaVerify = null;
        try {
            ecdsaVerify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ecdsaVerify.initVerify(pk);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            ecdsaVerify.update(message);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        try {
            Boolean verified = ecdsaVerify.verify(signature);
            tw.setText( tw.getText() + "Signature verified: " + verified.toString() + "\n" );
        } catch (SignatureException e) {
            e.printStackTrace();
        }



    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
