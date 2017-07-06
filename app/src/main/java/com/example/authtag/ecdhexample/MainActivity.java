package com.example.authtag.ecdhexample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;
import org.spongycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
