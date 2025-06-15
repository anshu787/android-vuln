package com.example.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.database.sqlite.SQLiteDatabase;
import javax.crypto.Cipher;

public class MainActivity extends Activity {
    
    // Hardcoded secrets
    private static final String API_KEY = "hardcoded_api_key_12345";
    private static final String PASSWORD = "super_secret_password";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Vulnerable WebView
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        
        // Weak crypto
        try {
            Cipher cipher = Cipher.getInstance("DES");
        } catch (Exception e) {}
        
        // SQL injection vulnerability
        SQLiteDatabase db = null;
        String userInput = "malicious_input";
        db.rawQuery("SELECT * FROM users WHERE id = " + userInput, null);
        
        // HTTP URL usage
        String apiUrl = "http://api.example.com/data";
    }
}
